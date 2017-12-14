// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::{HashSet, HashMap, BTreeMap, VecDeque};
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering as AtomicOrdering};
use std::time::{Instant};
use time::precise_time_ns;
use itertools::Itertools;

// util
use hash::keccak;
use timer::PerfTimer;
use bytes::Bytes;
use util::{Address, DBValue};
use journaldb;
use util_error::UtilError;
use trie::{TrieSpec, TrieFactory, Trie};
use kvdb::{KeyValueDB, DBTransaction};

// other
use bigint::prelude::U256;
use bigint::hash::H256;
use basic_types::Seal;
use block::*;
use blockchain::{BlockChain, BlockProvider,  TreeRoute, ImportRoute};
use blockchain::extras::TransactionAddress;
use client::Error as ClientError;
use client::{
	BlockId, TransactionId, UncleId, TraceId, ClientConfig,
	TraceFilter, CallAnalytics, BlockImportError, Mode,
	ChainNotify, PruningInfo,
};
use encoded;
use engines::{EthEngine, EpochTransition};
use error::{ImportError, ExecutionError, CallError, BlockError, ImportResult, Error as EthcoreError};
use vm::{EnvInfo, LastHashes};
use evm::{Factory as EvmFactory, Schedule};
use executive::{Executive, Executed, TransactOptions, contract_address};
use factory::Factories;
use futures::{future, Future};
use header::{BlockNumber, Header};
use io::*;
use log_entry::LocalizedLogEntry;
use parking_lot::{Mutex, RwLock, MutexGuard};
use rand::OsRng;
use receipt::{Receipt, LocalizedReceipt};
use rlp::UntrustedRlp;
use service::ClientIoMessage;
use spec::Spec;
use state_db::StateDB;
use state::{self, State};
use trace;
use trace::{TraceDB, ImportRequest as TraceImportRequest, LocalizedTrace, Database as TraceDatabase};
use trace::FlatTransactionTraces;
use transaction::{LocalizedTransaction, UnverifiedTransaction, SignedTransaction, Transaction, PendingTransaction, Action};
use types::filter::Filter;
use types::mode::Mode as IpcMode;
use views::BlockView;

// re-export
pub use types::blockchain_info::BlockChainInfo;
pub use types::block_status::BlockStatus;
pub use blockchain::CacheSize as BlockChainCacheSize;

const MAX_TX_QUEUE_SIZE: usize = 4096;
const MAX_QUEUE_SIZE_TO_SLEEP_ON: usize = 2;
const MIN_HISTORY_SIZE: u64 = 8;

/// Report on the status of a client.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct ClientReport {
	/// How many blocks have been imported so far.
	pub blocks_imported: usize,
	/// How many transactions have been applied so far.
	pub transactions_applied: usize,
	/// How much gas has been processed so far.
	pub gas_processed: U256,
	/// Memory used by state DB
	pub state_db_mem: usize,
}

impl ClientReport {
	/// Alter internal reporting to reflect the additional `block` has been processed.
	pub fn accrue_block(&mut self, block: &PreverifiedBlock) {
		self.blocks_imported += 1;
		self.transactions_applied += block.transactions.len();
		self.gas_processed = self.gas_processed + block.header.gas_used().clone();
	}
}

impl<'a> ::std::ops::Sub<&'a ClientReport> for ClientReport {
	type Output = Self;

	fn sub(mut self, other: &'a ClientReport) -> Self {
		let higher_mem = ::std::cmp::max(self.state_db_mem, other.state_db_mem);
		let lower_mem = ::std::cmp::min(self.state_db_mem, other.state_db_mem);

		self.blocks_imported -= other.blocks_imported;
		self.transactions_applied -= other.transactions_applied;
		self.gas_processed = self.gas_processed - other.gas_processed;
		self.state_db_mem  = higher_mem - lower_mem;

		self
	}
}

struct SleepState {
	last_activity: Option<Instant>,
	last_autosleep: Option<Instant>,
}

impl SleepState {
	fn new(awake: bool) -> Self {
		SleepState {
			last_activity: match awake { false => None, true => Some(Instant::now()) },
			last_autosleep: match awake { false => Some(Instant::now()), true => None },
		}
	}
}

/// Blockchain database client backed by a persistent database. Owns and manages a blockchain and a block queue.
/// Call `import_block()` to import a block asynchronously; `flush_queue()` flushes the queue.
pub struct Client {
	enabled: AtomicBool,
	mode: Mutex<Mode>,
	chain: RwLock<Arc<BlockChain>>,
	tracedb: RwLock<TraceDB<BlockChain>>,
	engine: Arc<EthEngine>,
	config: ClientConfig,
	pruning: journaldb::Algorithm,
	db: RwLock<Arc<KeyValueDB>>,
	state_db: Mutex<StateDB>,
	report: RwLock<ClientReport>,
	import_lock: Mutex<()>,
	sleep_state: Mutex<SleepState>,
	liveness: AtomicBool,
	io_channel: Mutex<IoChannel<ClientIoMessage>>,
	notify: RwLock<Vec<Weak<ChainNotify>>>,
	queue_transactions: AtomicUsize,
	last_hashes: RwLock<VecDeque<H256>>,
	factories: Factories,
	history: u64,
	rng: Mutex<OsRng>,
	on_user_defaults_change: Mutex<Option<Box<FnMut(Option<Mode>) + 'static + Send>>>,
	exit_handler: Mutex<Option<Box<Fn(bool, Option<String>) + 'static + Send>>>,
}

impl Client {
	/// Create a new client with given parameters.
	/// The database is assumed to have been initialized with the correct columns.
	pub fn new(
		config: ClientConfig,
		spec: &Spec,
		db: Arc<KeyValueDB>,
		message_channel: IoChannel<ClientIoMessage>,
	) -> Result<Arc<Client>, ::error::Error> {
		let trie_spec = match config.fat_db {
			true => TrieSpec::Fat,
			false => TrieSpec::Secure,
		};

		let trie_factory = TrieFactory::new(trie_spec);
		let factories = Factories {
			vm: EvmFactory::new(config.vm_type.clone(), config.jump_table_size),
			trie: trie_factory,
			accountdb: Default::default(),
		};

		let journal_db = journaldb::new(db.clone(), config.pruning, ::db::COL_STATE);
		let mut state_db = StateDB::new(journal_db, config.state_cache_size);
		if state_db.journal_db().is_empty() {
			// Sets the correct state root.
			state_db = spec.ensure_db_good(state_db, &factories)?;
			let mut batch = DBTransaction::new();
			state_db.journal_under(&mut batch, 0, &spec.genesis_header().hash())?;
			db.write(batch).map_err(ClientError::Database)?;
		}

		let gb = spec.genesis_block();
		let chain = Arc::new(BlockChain::new(config.blockchain.clone(), &gb, db.clone()));
		let tracedb = RwLock::new(TraceDB::new(config.tracing.clone(), db.clone(), chain.clone()));

		trace!("Cleanup journal: DB Earliest = {:?}, Latest = {:?}", state_db.journal_db().earliest_era(), state_db.journal_db().latest_era());

		let history = if config.history < MIN_HISTORY_SIZE {
			info!(target: "client", "Ignoring pruning history parameter of {}\
				, falling back to minimum of {}",
				config.history, MIN_HISTORY_SIZE);
			MIN_HISTORY_SIZE
		} else {
			config.history
		};

		if !chain.block_header(&chain.best_block_hash()).map_or(true, |h| state_db.journal_db().contains(h.state_root())) {
			warn!("State root not found for block #{} ({})", chain.best_block_number(), chain.best_block_hash().hex());
		}

		let engine = spec.engine.clone();


		let awake = match config.mode { Mode::Dark(..) | Mode::Off => false, _ => true };

		let client = Arc::new(Client {
			enabled: AtomicBool::new(true),
			sleep_state: Mutex::new(SleepState::new(awake)),
			liveness: AtomicBool::new(awake),
			mode: Mutex::new(config.mode.clone()),
			chain: RwLock::new(chain),
			tracedb: tracedb,
			engine: engine,
			pruning: config.pruning.clone(),
			config: config,
			db: RwLock::new(db),
			state_db: Mutex::new(state_db),
			report: RwLock::new(Default::default()),
			import_lock: Mutex::new(()),
			io_channel: Mutex::new(message_channel),
			notify: RwLock::new(Vec::new()),
			queue_transactions: AtomicUsize::new(0),
			last_hashes: RwLock::new(VecDeque::new()),
			factories: factories,
			history: history,
			rng: Mutex::new(OsRng::new().map_err(UtilError::from)?),
			ancient_verifier: Mutex::new(None),
			on_user_defaults_change: Mutex::new(None),
			exit_handler: Mutex::new(None),
		});

		// ensure genesis epoch proof in the DB.
		{
			let chain = client.chain.read();
			let gh = spec.genesis_header();
			if chain.epoch_transition(0, gh.hash()).is_none() {
				trace!(target: "client", "No genesis transition found.");

				let proof = client.with_proving_caller(
					BlockId::Number(0),
					|call| client.engine.genesis_epoch_data(&gh, call)
				);
				let proof = match proof {
					Ok(proof) => proof,
					Err(e) => {
						warn!(target: "client", "Error generating genesis epoch data: {}. Snapshots generated may not be complete.", e);
						Vec::new()
					}
				};

				debug!(target: "client", "Obtained genesis transition proof: {:?}", proof);

				let mut batch = DBTransaction::new();
				chain.insert_epoch_transition(&mut batch, 0, EpochTransition {
					block_hash: gh.hash(),
					block_number: 0,
					proof: proof,
				});

				client.db.read().write_buffered(batch);
			}
		}

		// ensure buffered changes are flushed.
		client.db.read().flush().map_err(ClientError::Database)?;
		Ok(client)
	}

	/// Wakes up client if it's a sleep.
	pub fn keep_alive(&self) {
		let should_wake = match *self.mode.lock() {
			Mode::Dark(..) | Mode::Passive(..) => true,
			_ => false,
		};
		if should_wake {
			self.wake_up();
			(*self.sleep_state.lock()).last_activity = Some(Instant::now());
		}
	}

	/// Adds an actor to be notified on certain events
	pub fn add_notify(&self, target: Arc<ChainNotify>) {
		self.notify.write().push(Arc::downgrade(&target));
	}

	/// Set a closure to call when we want to restart the client
	pub fn set_exit_handler<F>(&self, f: F) where F: Fn(bool, Option<String>) + 'static + Send {
		*self.exit_handler.lock() = Some(Box::new(f));
	}

	/// Returns engine reference.
	pub fn engine(&self) -> &EthEngine {
		&*self.engine
	}

	fn notify<F>(&self, f: F) where F: Fn(&ChainNotify) {
		for np in self.notify.read().iter() {
			if let Some(n) = np.upgrade() {
				f(&*n);
			}
		}
	}

	/// Register an action to be done if a mode/spec_name change happens.
	pub fn on_user_defaults_change<F>(&self, f: F) where F: 'static + FnMut(Option<Mode>) + Send {
		*self.on_user_defaults_change.lock() = Some(Box::new(f));
	}

	/// Flush the block import queue.
	pub fn flush_queue(&self) {
		self.block_queue.flush();
		while !self.block_queue.queue_info().is_empty() {
			self.import_verified_blocks();
		}
	}

	/// The env info as of the best block.
	pub fn latest_env_info(&self) -> EnvInfo {
		self.env_info(BlockId::Latest).expect("Best block header always stored; qed")
	}

	/// The env info as of a given block.
	/// returns `None` if the block unknown.
	pub fn env_info(&self, id: BlockId) -> Option<EnvInfo> {
		self.block_header(id).map(|header| {
			EnvInfo {
				number: header.number(),
				author: header.author(),
				timestamp: header.timestamp(),
				difficulty: header.difficulty(),
				last_hashes: self.build_last_hashes(header.parent_hash()),
				gas_used: U256::default(),
				gas_limit: header.gas_limit(),
			}
		})
	}

	fn build_last_hashes(&self, parent_hash: H256) -> Arc<LastHashes> {
		{
			let hashes = self.last_hashes.read();
			if hashes.front().map_or(false, |h| h == &parent_hash) {
				let mut res = Vec::from(hashes.clone());
				res.resize(256, H256::default());
				return Arc::new(res);
			}
		}
		let mut last_hashes = LastHashes::new();
		last_hashes.resize(256, H256::default());
		last_hashes[0] = parent_hash;
		let chain = self.chain.read();
		for i in 0..255 {
			match chain.block_details(&last_hashes[i]) {
				Some(details) => {
					last_hashes[i + 1] = details.parent.clone();
				},
				None => break,
			}
		}
		let mut cached_hashes = self.last_hashes.write();
		*cached_hashes = VecDeque::from(last_hashes.clone());
		Arc::new(last_hashes)
	}

	fn check_and_close_block(&self, block: &PreverifiedBlock) -> Result<LockedBlock, ()> {
		let engine = &*self.engine;
		let header = &block.header;

		let chain = self.chain.read();
		// Check the block isn't so old we won't be able to enact it.
		let best_block_number = chain.best_block_number();
		if self.pruning_info().earliest_state > header.number() {
			warn!(target: "client", "Block import failed for #{} ({})\nBlock is ancient (current best block: #{}).", header.number(), header.hash(), best_block_number);
			return Err(());
		}

		// Check if parent is in chain
		let parent = match chain.block_header(header.parent_hash()) {
			Some(h) => h,
			None => {
				warn!(target: "client", "Block import failed for #{} ({}): Parent not found ({}) ", header.number(), header.hash(), header.parent_hash());
				return Err(());
			}
		};

		// Verify Block Family
		let verify_family_result = self.verifier.verify_block_family(
			header,
			&parent,
			engine,
			Some((&block.bytes, &block.transactions, &**chain, self)),
		);

		if let Err(e) = verify_family_result {
			warn!(target: "client", "Stage 3 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
			return Err(());
		};

		let verify_external_result = self.verifier.verify_block_external(header, engine);
		if let Err(e) = verify_external_result {
			warn!(target: "client", "Stage 4 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
			return Err(());
		};

		// Enact Verified Block
		let last_hashes = self.build_last_hashes(header.parent_hash().clone());
		let db = self.state_db.lock().boxed_clone_canon(header.parent_hash());

		let is_epoch_begin = chain.epoch_transition(parent.number(), *header.parent_hash()).is_some();
		let enact_result = enact_verified(block,
			engine,
			self.tracedb.read().tracing_enabled(),
			db,
			&parent,
			last_hashes,
			self.factories.clone(),
			is_epoch_begin,
		);
		let mut locked_block = enact_result.map_err(|e| {
			warn!(target: "client", "Block import failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
		})?;

		if header.number() < self.engine().params().validate_receipts_transition && header.receipts_root() != locked_block.block().header().receipts_root() {
			locked_block = locked_block.strip_receipts();
		}

		// Final Verification
		if let Err(e) = self.verifier.verify_block_final(header, locked_block.block().header()) {
			warn!(target: "client", "Stage 5 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
			return Err(());
		}

		Ok(locked_block)
	}

	fn calculate_enacted_retracted(&self, import_results: &[ImportRoute]) -> (Vec<H256>, Vec<H256>) {
		fn map_to_vec(map: Vec<(H256, bool)>) -> Vec<H256> {
			map.into_iter().map(|(k, _v)| k).collect()
		}

		// In ImportRoute we get all the blocks that have been enacted and retracted by single insert.
		// Because we are doing multiple inserts some of the blocks that were enacted in import `k`
		// could be retracted in import `k+1`. This is why to understand if after all inserts
		// the block is enacted or retracted we iterate over all routes and at the end final state
		// will be in the hashmap
		let map = import_results.iter().fold(HashMap::new(), |mut map, route| {
			for hash in &route.enacted {
				map.insert(hash.clone(), true);
			}
			for hash in &route.retracted {
				map.insert(hash.clone(), false);
			}
			map
		});

		// Split to enacted retracted (using hashmap value)
		let (enacted, retracted) = map.into_iter().partition(|&(_k, v)| v);
		// And convert tuples to keys
		(map_to_vec(enacted), map_to_vec(retracted))
	}

	/// This is triggered by a message coming from a block queue when the block is ready for insertion
	pub fn import_verified_blocks(&self) -> usize {

		// Shortcut out if we know we're incapable of syncing the chain.
		if !self.enabled.load(AtomicOrdering::Relaxed) {
			return 0;
		}

		let max_blocks_to_import = 4;
		let (imported_blocks, import_results, invalid_blocks, imported, proposed_blocks, duration, is_empty) = {
			let mut imported_blocks = Vec::with_capacity(max_blocks_to_import);
			let mut invalid_blocks = HashSet::new();
			let mut proposed_blocks = Vec::with_capacity(max_blocks_to_import);
			let mut import_results = Vec::with_capacity(max_blocks_to_import);

			let _import_lock = self.import_lock.lock();
			let blocks = self.block_queue.drain(max_blocks_to_import);
			if blocks.is_empty() {
				return 0;
			}
			let _timer = PerfTimer::new("import_verified_blocks");
			let start = precise_time_ns();

			for block in blocks {
				let header = &block.header;
				let is_invalid = invalid_blocks.contains(header.parent_hash());
				if is_invalid {
					invalid_blocks.insert(header.hash());
					continue;
				}
				if let Ok(closed_block) = self.check_and_close_block(&block) {
					if self.engine.is_proposal(&block.header) {
						self.block_queue.mark_as_good(&[header.hash()]);
						proposed_blocks.push(block.bytes);
					} else {
						imported_blocks.push(header.hash());

						let route = self.commit_block(closed_block, &header, &block.bytes);
						import_results.push(route);

						self.report.write().accrue_block(&block);
					}
				} else {
					invalid_blocks.insert(header.hash());
				}
			}

			let imported = imported_blocks.len();
			let invalid_blocks = invalid_blocks.into_iter().collect::<Vec<H256>>();

			if !invalid_blocks.is_empty() {
				self.block_queue.mark_as_bad(&invalid_blocks);
			}
			let is_empty = self.block_queue.mark_as_good(&imported_blocks);
			let duration_ns = precise_time_ns() - start;
			(imported_blocks, import_results, invalid_blocks, imported, proposed_blocks, duration_ns, is_empty)
		};

		{
			if !imported_blocks.is_empty() && is_empty {
				let (enacted, retracted) = self.calculate_enacted_retracted(&import_results);

				self.notify(|notify| {
					notify.new_blocks(
						imported_blocks.clone(),
						invalid_blocks.clone(),
						enacted.clone(),
						retracted.clone(),
						Vec::new(),
						proposed_blocks.clone(),
						duration,
					);
				});
			}
		}

		self.db.read().flush().expect("DB flush failed.");
		imported
	}

	/// Import a block with transaction receipts.
	/// The block is guaranteed to be the next best blocks in the first block sequence.
	/// Does no sealing or transaction validation.
	fn import_old_block(&self, block_bytes: Bytes, receipts_bytes: Bytes) -> Result<H256, ::error::Error> {
		let block = BlockView::new(&block_bytes);
		let header = block.header();
		let receipts = ::rlp::decode_list(&receipts_bytes);
		let hash = header.hash();
		let _import_lock = self.import_lock.lock();

		self.db.read().flush().expect("DB flush failed.");
		Ok(hash)
	}

	// NOTE: the header of the block passed here is not necessarily sealed, as
	// it is for reconstructing the state transition.
	//
	// The header passed is from the original block data and is sealed.
	fn commit_block<B>(&self, block: B, header: &Header, block_data: &[u8]) -> ImportRoute where B: IsBlock + Drain {
		let hash = &header.hash();
		let number = header.number();
		let parent = header.parent_hash();
		let chain = self.chain.read();

		// Commit results
		let receipts = block.receipts().to_owned();
		let traces = block.traces().clone().unwrap_or_else(Vec::new);
		let traces: Vec<FlatTransactionTraces> = traces.into_iter()
			.map(Into::into)
			.collect();

		assert_eq!(header.hash(), BlockView::new(block_data).header_view().hash());

		//let traces = From::from(block.traces().clone().unwrap_or_else(Vec::new));

		let mut batch = DBTransaction::new();

		// CHECK! I *think* this is fine, even if the state_root is equal to another
		// already-imported block of the same number.
		// TODO: Prove it with a test.
		let mut state = block.drain();

		// check epoch end signal, potentially generating a proof on the current
		// state.
		self.check_epoch_end_signal(
			&header,
			block_data,
			&receipts,
			&state,
			&chain,
			&mut batch,
		);

		state.journal_under(&mut batch, number, hash).expect("DB commit failed");
		let route = chain.insert_block(&mut batch, block_data, receipts.clone());

		self.tracedb.read().import(&mut batch, TraceImportRequest {
			traces: traces.into(),
			block_hash: hash.clone(),
			block_number: number,
			enacted: route.enacted.clone(),
			retracted: route.retracted.len()
		});

		let is_canon = route.enacted.last().map_or(false, |h| h == hash);
		state.sync_cache(&route.enacted, &route.retracted, is_canon);
		// Final commit to the DB
		self.db.read().write_buffered(batch);
		chain.commit();

		self.check_epoch_end(&header, &chain);

		self.update_last_hashes(&parent, hash);

		route
	}

	// check for epoch end signal and write pending transition if it occurs.
	// state for the given block must be available.
	fn check_epoch_end_signal(
		&self,
		header: &Header,
		block_bytes: &[u8],
		receipts: &[Receipt],
		state_db: &StateDB,
		chain: &BlockChain,
		batch: &mut DBTransaction,
	) {
		use engines::EpochChange;

		let hash = header.hash();
		let auxiliary = ::machine::AuxiliaryData {
			bytes: Some(block_bytes),
			receipts: Some(&receipts),
		};

		match self.engine.signals_epoch_end(header, auxiliary) {
			EpochChange::Yes(proof) => {
				use engines::epoch::PendingTransition;
				use engines::Proof;

				let proof = match proof {
					Proof::Known(proof) => proof,
					Proof::WithState(with_state) => {
						let env_info = EnvInfo {
							number: header.number(),
							author: header.author().clone(),
							timestamp: header.timestamp(),
							difficulty: header.difficulty().clone(),
							last_hashes: self.build_last_hashes(header.parent_hash().clone()),
							gas_used: U256::default(),
							gas_limit: u64::max_value().into(),
						};

						let call = move |addr, data| {
							let mut state_db = state_db.boxed_clone();
							let backend = ::state::backend::Proving::new(state_db.as_hashdb_mut());

							let transaction =
								self.contract_call_tx(BlockId::Hash(*header.parent_hash()), addr, data);

							let mut state = State::from_existing(
								backend,
								header.state_root().clone(),
								self.engine.account_start_nonce(header.number()),
								self.factories.clone(),
							).expect("state known to be available for just-imported block; qed");

							let options = TransactOptions::with_no_tracing().dont_check_nonce();
							let res = Executive::new(&mut state, &env_info, self.engine.machine())
								.transact(&transaction, options);

							let res = match res {
								Err(ExecutionError::Internal(e)) =>
									Err(format!("Internal error: {}", e)),
								Err(e) => {
									trace!(target: "client", "Proved call failed: {}", e);
									Ok((Vec::new(), state.drop().1.extract_proof()))
								}
								Ok(res) => Ok((res.output, state.drop().1.extract_proof())),
							};

							res.map(|(output, proof)| (output, proof.into_iter().map(|x| x.into_vec()).collect()))
						};

						match with_state.generate_proof(&call) {
							Ok(proof) => proof,
							Err(e) => {
								warn!(target: "client", "Failed to generate transition proof for block {}: {}", hash, e);
								warn!(target: "client", "Snapshots produced by this client may be incomplete");
								Vec::new()
							}
						}
					}
				};

				debug!(target: "client", "Block {} signals epoch end.", hash);

				let pending = PendingTransition { proof: proof };
				chain.insert_pending_transition(batch, hash, pending);
			},
			EpochChange::No => {},
			EpochChange::Unsure(_) => {
				warn!(target: "client", "Detected invalid engine implementation.");
				warn!(target: "client", "Engine claims to require more block data, but everything provided.");
			}
		}
	}

	// check for ending of epoch and write transition if it occurs.
	fn check_epoch_end<'a>(&self, header: &'a Header, chain: &BlockChain) {
		let is_epoch_end = self.engine.is_epoch_end(
			header,
			&(|hash| chain.block_header(&hash)),
			&(|hash| chain.get_pending_transition(hash)), // TODO: limit to current epoch.
		);

		if let Some(proof) = is_epoch_end {
			debug!(target: "client", "Epoch transition at block {}", header.hash());

			let mut batch = DBTransaction::new();
			chain.insert_epoch_transition(&mut batch, header.number(), EpochTransition {
				block_hash: header.hash(),
				block_number: header.number(),
				proof: proof,
			});

			// always write the batch directly since epoch transition proofs are
			// fetched from a DB iterator and DB iterators are only available on
			// flushed data.
			self.db.read().write(batch).expect("DB flush failed");
		}
	}

	// use a state-proving closure for the given block.
	fn with_proving_caller<F, T>(&self, id: BlockId, with_call: F) -> T
		where F: FnOnce(&::machine::Call) -> T
	{
		let call = |a, d| {
			let tx = self.contract_call_tx(id, a, d);
			let (result, items) = self.prove_transaction(tx, id)
				.ok_or_else(|| format!("Unable to make call. State unavailable?"))?;

			let items = items.into_iter().map(|x| x.to_vec()).collect();
			Ok((result, items))
		};

		with_call(&call)
	}

	fn update_last_hashes(&self, parent: &H256, hash: &H256) {
		let mut hashes = self.last_hashes.write();
		if hashes.front().map_or(false, |h| h == parent) {
			if hashes.len() > 255 {
				hashes.pop_back();
			}
			hashes.push_front(hash.clone());
		}
	}

	/// Import transactions from the IO queue
	pub fn import_queued_transactions(&self, transactions: &[Bytes], peer_id: usize) -> usize {
        0
	}

	/// Replace io channel. Useful for testing.
	pub fn set_io_channel(&self, io_channel: IoChannel<ClientIoMessage>) {
		*self.io_channel.lock() = io_channel;
	}

	/// Attempt to get a copy of a specific block's final state.
	///
	/// This will not fail if given BlockId::Latest.
	/// Otherwise, this can fail (but may not) if the DB prunes state or the block
	/// is unknown.
	pub fn state_at(&self, id: BlockId) -> Option<State<StateDB>> {
		// fast path for latest state.
		match id.clone() {
			BlockId::Pending => return Some(self.state()), 
			BlockId::Latest => return Some(self.state()),
			_ => {},
		}

		let block_number = match self.block_number(id) {
			Some(num) => num,
			None => return None,
		};

		self.block_header(id).and_then(|header| {
			let db = self.state_db.lock().boxed_clone();

			// early exit for pruned blocks
			if db.is_pruned() && self.pruning_info().earliest_state > block_number {
				return None;
			}

			let root = header.state_root();
			State::from_existing(db, root, self.engine.account_start_nonce(block_number), self.factories.clone()).ok()
		})
	}

	/// Attempt to get a copy of a specific block's beginning state.
	///
	/// This will not fail if given BlockId::Latest.
	/// Otherwise, this can fail (but may not) if the DB prunes state.
	pub fn state_at_beginning(&self, id: BlockId) -> Option<State<StateDB>> {
		// fast path for latest state.
		match id {
			BlockId::Pending => self.state_at(BlockId::Latest),
			id => match self.block_number(id) {
				None | Some(0) => None,
				Some(n) => self.state_at(BlockId::Number(n - 1)),
			}
		}
	}

	/// Get a copy of the best block's state.
	pub fn state(&self) -> State<StateDB> {
		let header = self.best_block_header();
		State::from_existing(
			self.state_db.lock().boxed_clone_canon(&header.hash()),
			header.state_root(),
			self.engine.account_start_nonce(header.number()),
			self.factories.clone())
		.expect("State root of best block header always valid.")
	}

	/// Get info on the cache.
	pub fn blockchain_cache_info(&self) -> BlockChainCacheSize {
		self.chain.read().cache_size()
	}

	/// Get the report.
	pub fn report(&self) -> ClientReport {
		let mut report = self.report.read().clone();
		report.state_db_mem = self.state_db.lock().mem_used();
		report
	}

	/// Tick the client.
	// TODO: manage by real events.
	pub fn tick(&self, prevent_sleep: bool) {
		self.check_garbage();
		if !prevent_sleep {
			self.check_snooze();
		}
	}

	fn check_garbage(&self) {
		self.chain.read().collect_garbage();
		self.block_queue.collect_garbage();
		self.tracedb.read().collect_garbage();
	}

	fn check_snooze(&self) {
		let mode = self.mode.lock().clone();
		match mode {
			Mode::Dark(timeout) => {
				let mut ss = self.sleep_state.lock();
				if let Some(t) = ss.last_activity {
					if Instant::now() > t + timeout {
						self.sleep();
						ss.last_activity = None;
					}
				}
			}
			Mode::Passive(timeout, wakeup_after) => {
				let mut ss = self.sleep_state.lock();
				let now = Instant::now();
				if let Some(t) = ss.last_activity {
					if now > t + timeout {
						self.sleep();
						ss.last_activity = None;
						ss.last_autosleep = Some(now);
					}
				}
				if let Some(t) = ss.last_autosleep {
					if now > t + wakeup_after {
						self.wake_up();
						ss.last_activity = Some(now);
						ss.last_autosleep = None;
					}
				}
			}
			_ => {}
		}
	}
	/// Ask the client what the history parameter is.
	pub fn pruning_history(&self) -> u64 {
		self.history
	}

	fn block_hash(chain: &BlockChain, id: BlockId) -> Option<H256> {
		match id {
			BlockId::Hash(hash) => Some(hash),
			BlockId::Number(number) => chain.block_hash(number),
			BlockId::Earliest => chain.block_hash(0),
			BlockId::Latest => Some(chain.best_block_hash()),
			BlockId::Pending => None 
		}
	}


	fn wake_up(&self) {
		if !self.liveness.load(AtomicOrdering::Relaxed) {
			self.liveness.store(true, AtomicOrdering::Relaxed);
			self.notify(|n| n.start());
			info!(target: "mode", "wake_up: Waking.");
		}
	}

	fn sleep(&self) {
		if self.liveness.load(AtomicOrdering::Relaxed) {
			// only sleep if the import queue is mostly empty.
			if self.queue_info().total_queue_size() <= MAX_QUEUE_SIZE_TO_SLEEP_ON {
				self.liveness.store(false, AtomicOrdering::Relaxed);
				self.notify(|n| n.stop());
				info!(target: "mode", "sleep: Sleeping.");
			} else {
				info!(target: "mode", "sleep: Cannot sleep - syncing ongoing.");
			}
		}
	}

	// transaction for calling contracts from services like engine.
	// from the null sender, with 50M gas.
	fn contract_call_tx(&self, block_id: BlockId, address: Address, data: Bytes) -> SignedTransaction {
		let from = Address::default();
		Transaction {
			nonce: self.nonce(&from, block_id).unwrap_or_else(|| self.engine.account_start_nonce(0)),
			action: Action::Call(address),
			gas: U256::from(50_000_000),
			gas_price: U256::default(),
			value: U256::default(),
			data: data,
		}.fake_sign(from)
	}

	fn do_virtual_call(&self, env_info: &EnvInfo, state: &mut State<StateDB>, t: &SignedTransaction, analytics: CallAnalytics) -> Result<Executed, CallError> {
		fn call<V, T>(
			state: &mut State<StateDB>,
			env_info: &EnvInfo,
			machine: &::machine::EthereumMachine,
			state_diff: bool,
			transaction: &SignedTransaction,
			options: TransactOptions<T, V>,
		) -> Result<Executed<T::Output, V::Output>, CallError> where
			T: trace::Tracer,
			V: trace::VMTracer,
		{
			let options = options
				.dont_check_nonce()
				.save_output_from_contract();
			let original_state = if state_diff { Some(state.clone()) } else { None };

			let mut ret = Executive::new(state, env_info, machine).transact_virtual(transaction, options)?;

			if let Some(original) = original_state {
				ret.state_diff = Some(state.diff_from(original).map_err(ExecutionError::from)?);
			}
			Ok(ret)
		}

		let state_diff = analytics.state_diffing;
		let machine = self.engine.machine();

		match (analytics.transaction_tracing, analytics.vm_tracing) {
			(true, true) => call(state, env_info, machine, state_diff, t, TransactOptions::with_tracing_and_vm_tracing()),
			(true, false) => call(state, env_info, machine, state_diff, t, TransactOptions::with_tracing()),
			(false, true) => call(state, env_info, machine, state_diff, t, TransactOptions::with_vm_tracing()),
			(false, false) => call(state, env_info, machine, state_diff, t, TransactOptions::with_no_tracing()),
		}
	}

	fn block_number_ref(&self, id: &BlockId) -> Option<BlockNumber> {
		match *id {
			BlockId::Number(number) => Some(number),
			BlockId::Hash(ref hash) => self.chain.read().block_number(hash),
			BlockId::Earliest => Some(0),
			BlockId::Latest => Some(self.chain.read().best_block_number()),
			BlockId::Pending => Some(self.chain.read().best_block_number() + 1),
		}
	}
}


impl Drop for Client {
	fn drop(&mut self) {
		self.engine.stop();
	}
}

/// Returns `LocalizedReceipt` given `LocalizedTransaction`
/// and a vector of receipts from given block up to transaction index.
fn transaction_receipt(machine: &::machine::EthereumMachine, mut tx: LocalizedTransaction, mut receipts: Vec<Receipt>) -> LocalizedReceipt {
	assert_eq!(receipts.len(), tx.transaction_index + 1, "All previous receipts are provided.");

	let sender = tx.sender();
	let receipt = receipts.pop().expect("Current receipt is provided; qed");
	let prior_gas_used = match tx.transaction_index {
		0 => 0.into(),
		i => receipts.get(i - 1).expect("All previous receipts are provided; qed").gas_used,
	};
	let no_of_logs = receipts.into_iter().map(|receipt| receipt.logs.len()).sum::<usize>();
	let transaction_hash = tx.hash();
	let block_hash = tx.block_hash;
	let block_number = tx.block_number;
	let transaction_index = tx.transaction_index;

	LocalizedReceipt {
		transaction_hash: transaction_hash,
		transaction_index: transaction_index,
		block_hash: block_hash,
		block_number: block_number,
		cumulative_gas_used: receipt.gas_used,
		gas_used: receipt.gas_used - prior_gas_used,
		contract_address: match tx.action {
			Action::Call(_) => None,
			Action::Create => Some(contract_address(machine.create_address_scheme(block_number), &sender, &tx.nonce, &tx.data).0)
		},
		logs: receipt.logs.into_iter().enumerate().map(|(i, log)| LocalizedLogEntry {
			entry: log,
			block_hash: block_hash,
			block_number: block_number,
			transaction_hash: transaction_hash,
			transaction_index: transaction_index,
			transaction_log_index: i,
			log_index: no_of_logs + i,
		}).collect(),
		log_bloom: receipt.log_bloom,
		outcome: receipt.outcome,
	}
}

#[cfg(test)]
mod tests {

	#[test]
	fn should_return_correct_log_index() {
		use hash::keccak;
		use super::transaction_receipt;
		use ethkey::KeyPair;
		use log_entry::{LogEntry, LocalizedLogEntry};
		use receipt::{Receipt, LocalizedReceipt, TransactionOutcome};
		use transaction::{Transaction, LocalizedTransaction, Action};

		// given
		let key = KeyPair::from_secret_slice(&keccak("test")).unwrap();
		let secret = key.secret();
		let machine = ::ethereum::new_frontier_test_machine();

		let block_number = 1;
		let block_hash = 5.into();
		let state_root = 99.into();
		let gas_used = 10.into();
		let raw_tx = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 21000.into(),
			action: Action::Call(10.into()),
			value: 0.into(),
			data: vec![],
		};
		let tx1 = raw_tx.clone().sign(secret, None);
		let transaction = LocalizedTransaction {
			signed: tx1.clone().into(),
			block_number: block_number,
			block_hash: block_hash,
			transaction_index: 1,
			cached_sender: Some(tx1.sender()),
		};
		let logs = vec![LogEntry {
			address: 5.into(),
			topics: vec![],
			data: vec![],
		}, LogEntry {
			address: 15.into(),
			topics: vec![],
			data: vec![],
		}];
		let receipts = vec![Receipt {
			outcome: TransactionOutcome::StateRoot(state_root),
			gas_used: 5.into(),
			log_bloom: Default::default(),
			logs: vec![logs[0].clone()],
		}, Receipt {
			outcome: TransactionOutcome::StateRoot(state_root),
			gas_used: gas_used,
			log_bloom: Default::default(),
			logs: logs.clone(),
		}];

		// when
		let receipt = transaction_receipt(&machine, transaction, receipts);

		// then
		assert_eq!(receipt, LocalizedReceipt {
			transaction_hash: tx1.hash(),
			transaction_index: 1,
			block_hash: block_hash,
			block_number: block_number,
			cumulative_gas_used: gas_used,
			gas_used: gas_used - 5.into(),
			contract_address: None,
			logs: vec![LocalizedLogEntry {
				entry: logs[0].clone(),
				block_hash: block_hash,
				block_number: block_number,
				transaction_hash: tx1.hash(),
				transaction_index: 1,
				transaction_log_index: 0,
				log_index: 1,
			}, LocalizedLogEntry {
				entry: logs[1].clone(),
				block_hash: block_hash,
				block_number: block_number,
				transaction_hash: tx1.hash(),
				transaction_index: 1,
				transaction_log_index: 1,
				log_index: 2,
			}],
			log_bloom: Default::default(),
			outcome: TransactionOutcome::StateRoot(state_root),
		});
	}
}
