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

//! Test client.

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrder};
use std::sync::Arc;
use std::collections::{HashMap, BTreeMap};
use std::mem;
use itertools::Itertools;
use rustc_hex::FromHex;
use hash::keccak;
use bigint::prelude::U256;
use bigint::hash::H256;
use parking_lot::RwLock;
use journaldb;
use util::{Address, DBValue};
use kvdb_memorydb;
use bytes::Bytes;
use rlp::*;
use ethkey::{Generator, Random};
use devtools::*;
use transaction::{Transaction, LocalizedTransaction, PendingTransaction, SignedTransaction, Action};
use blockchain::TreeRoute;
use client::{
	BlockChainInfo, BlockStatus, BlockId,
	TransactionId, UncleId, TraceId, TraceFilter, LastHashes, CallAnalytics, BlockImportError,
};
use db::{NUM_COLUMNS, COL_STATE};
use header::{Header as BlockHeader, BlockNumber};
use filter::Filter;
use log_entry::LocalizedLogEntry;
use receipt::{Receipt, LocalizedReceipt, TransactionOutcome};
use blockchain::extras::BlockReceipts;
use error::{ImportResult, Error as EthcoreError};
use evm::{Factory as EvmFactory, VMType};
use vm::Schedule;
use spec::Spec;
use types::basic_account::BasicAccount;
use types::mode::Mode;
use types::pruning_info::PruningInfo;

use block::{OpenBlock, SealedBlock, ClosedBlock};
use executive::Executed;
use error::CallError;
use trace::LocalizedTrace;
use state_db::StateDB;
use encoded;

/// Test client.
pub struct TestBlockChainClient {
	/// Blocks.
	pub blocks: RwLock<HashMap<H256, Bytes>>,
	/// Mapping of numbers to hashes.
	pub numbers: RwLock<HashMap<usize, H256>>,
	/// Genesis block hash.
	pub genesis_hash: H256,
	/// Last block hash.
	pub last_hash: RwLock<H256>,
	/// Extra data do set for each block
	pub extra_data: Bytes,
	/// Difficulty.
	pub difficulty: RwLock<U256>,
	/// Balances.
	pub balances: RwLock<HashMap<Address, U256>>,
	/// Nonces.
	pub nonces: RwLock<HashMap<Address, U256>>,
	/// Storage.
	pub storage: RwLock<HashMap<(Address, H256), H256>>,
	/// Code.
	pub code: RwLock<HashMap<Address, Bytes>>,
	/// Execution result.
	pub execution_result: RwLock<Option<Result<Executed, CallError>>>,
	/// Transaction receipts.
	pub receipts: RwLock<HashMap<TransactionId, LocalizedReceipt>>,
	/// Logs
	pub logs: RwLock<Vec<LocalizedLogEntry>>,
	/// Block queue size.
	pub queue_size: AtomicUsize,
	/// Spec
	pub spec: Spec,
	/// VM Factory
	pub vm_factory: EvmFactory,
	/// Timestamp assigned to latest sealed block
	pub latest_block_timestamp: RwLock<u64>,
	/// Ancient block info.
	pub ancient_block: RwLock<Option<(H256, u64)>>,
	/// First block info.
	pub first_block: RwLock<Option<(H256, u64)>>,
	/// Traces to return
	pub traces: RwLock<Option<Vec<LocalizedTrace>>>,
	/// Pruning history size to report.
	pub history: RwLock<Option<u64>>,
}

/// Used for generating test client blocks.
#[derive(Clone)]
pub enum EachBlockWith {
	/// Plain block.
	Nothing,
	/// Block with an uncle.
	Uncle,
	/// Block with a transaction.
	Transaction,
	/// Block with an uncle and transaction.
	UncleAndTransaction
}

impl Default for TestBlockChainClient {
	fn default() -> Self {
		TestBlockChainClient::new()
	}
}

impl TestBlockChainClient {
	/// Creates new test client.
	pub fn new() -> Self {
		Self::new_with_extra_data(Bytes::new())
	}

	/// Creates new test client with specified extra data for each block
	pub fn new_with_extra_data(extra_data: Bytes) -> Self {
		let spec = Spec::new_test();
		TestBlockChainClient::new_with_spec_and_extra(spec, extra_data)
	}

	/// Create test client with custom spec.
	pub fn new_with_spec(spec: Spec) -> Self {
		TestBlockChainClient::new_with_spec_and_extra(spec, Bytes::new())
	}

	/// Create test client with custom spec and extra data.
	pub fn new_with_spec_and_extra(spec: Spec, extra_data: Bytes) -> Self {
		let genesis_block = spec.genesis_block();
		let genesis_hash = spec.genesis_header().hash();

		let mut client = TestBlockChainClient {
			blocks: RwLock::new(HashMap::new()),
			numbers: RwLock::new(HashMap::new()),
			genesis_hash: H256::new(),
			extra_data: extra_data,
			last_hash: RwLock::new(H256::new()),
			difficulty: RwLock::new(spec.genesis_header().difficulty().clone()),
			balances: RwLock::new(HashMap::new()),
			nonces: RwLock::new(HashMap::new()),
			storage: RwLock::new(HashMap::new()),
			code: RwLock::new(HashMap::new()),
			execution_result: RwLock::new(None),
			receipts: RwLock::new(HashMap::new()),
			logs: RwLock::new(Vec::new()),
			queue_size: AtomicUsize::new(0),
			spec: spec,
			vm_factory: EvmFactory::new(VMType::Interpreter, 1024 * 1024),
			latest_block_timestamp: RwLock::new(10_000_000),
			ancient_block: RwLock::new(None),
			first_block: RwLock::new(None),
			traces: RwLock::new(None),
			history: RwLock::new(None),
		};

		// insert genesis hash.
		client.blocks.get_mut().insert(genesis_hash, genesis_block);
		client.numbers.get_mut().insert(0, genesis_hash);
		*client.last_hash.get_mut() = genesis_hash;
		client.genesis_hash = genesis_hash;
		client
	}

	/// Set the transaction receipt result
	pub fn set_transaction_receipt(&self, id: TransactionId, receipt: LocalizedReceipt) {
		self.receipts.write().insert(id, receipt);
	}

	/// Set the execution result.
	pub fn set_execution_result(&self, result: Result<Executed, CallError>) {
		*self.execution_result.write() = Some(result);
	}

	/// Set the balance of account `address` to `balance`.
	pub fn set_balance(&self, address: Address, balance: U256) {
		self.balances.write().insert(address, balance);
	}

	/// Set nonce of account `address` to `nonce`.
	pub fn set_nonce(&self, address: Address, nonce: U256) {
		self.nonces.write().insert(address, nonce);
	}

	/// Set `code` at `address`.
	pub fn set_code(&self, address: Address, code: Bytes) {
		self.code.write().insert(address, code);
	}

	/// Set storage `position` to `value` for account `address`.
	pub fn set_storage(&self, address: Address, position: H256, value: H256) {
		self.storage.write().insert((address, position), value);
	}

	/// Set block queue size for testing
	pub fn set_queue_size(&self, size: usize) {
		self.queue_size.store(size, AtomicOrder::Relaxed);
	}

	/// Set timestamp assigned to latest sealed block
	pub fn set_latest_block_timestamp(&self, ts: u64) {
		*self.latest_block_timestamp.write() = ts;
	}

	/// Set logs to return for each logs call.
	pub fn set_logs(&self, logs: Vec<LocalizedLogEntry>) {
		*self.logs.write() = logs;
	}

	/// Add blocks to test client.
	pub fn add_blocks(&self, count: usize, with: EachBlockWith) {
		let len = self.numbers.read().len();
		for n in len..(len + count) {
			let mut header = BlockHeader::new();
			header.set_difficulty(From::from(n));
			header.set_parent_hash(self.last_hash.read().clone());
			header.set_number(n as BlockNumber);
			header.set_gas_limit(U256::from(1_000_000));
			header.set_extra_data(self.extra_data.clone());
			let uncles = match with {
				EachBlockWith::Uncle | EachBlockWith::UncleAndTransaction => {
					let mut uncles = RlpStream::new_list(1);
					let mut uncle_header = BlockHeader::new();
					uncle_header.set_difficulty(From::from(n));
					uncle_header.set_parent_hash(self.last_hash.read().clone());
					uncle_header.set_number(n as BlockNumber);
					uncles.append(&uncle_header);
					header.set_uncles_hash(keccak(uncles.as_raw()));
					uncles
				},
				_ => RlpStream::new_list(0)
			};
			let txs = match with {
				EachBlockWith::Transaction | EachBlockWith::UncleAndTransaction => {
					let mut txs = RlpStream::new_list(1);
					let keypair = Random.generate().unwrap();
					// Update nonces value
					self.nonces.write().insert(keypair.address(), U256::one());
					let tx = Transaction {
						action: Action::Create,
						value: U256::from(100),
						data: "3331600055".from_hex().unwrap(),
						gas: U256::from(100_000),
						gas_price: U256::from(200_000_000_000u64),
						nonce: U256::zero()
					};
					let signed_tx = tx.sign(keypair.secret(), None);
					txs.append(&signed_tx);
					txs.out()
				},
				_ => ::rlp::EMPTY_LIST_RLP.to_vec()
			};

			let mut rlp = RlpStream::new_list(3);
			rlp.append(&header);
			rlp.append_raw(&txs, 1);
			rlp.append_raw(uncles.as_raw(), 1);
			self.import_block(rlp.as_raw().to_vec()).unwrap();
		}
	}

	/// Make a bad block by setting invalid extra data.
	pub fn corrupt_block(&self, n: BlockNumber) {
		let hash = self.block_hash(BlockId::Number(n)).unwrap();
		let mut header: BlockHeader = self.block_header(BlockId::Number(n)).unwrap().decode();
		header.set_extra_data(b"This extra data is way too long to be considered valid".to_vec());
		let mut rlp = RlpStream::new_list(3);
		rlp.append(&header);
		rlp.append_raw(&::rlp::NULL_RLP, 1);
		rlp.append_raw(&::rlp::NULL_RLP, 1);
		self.blocks.write().insert(hash, rlp.out());
	}

	/// Make a bad block by setting invalid parent hash.
	pub fn corrupt_block_parent(&self, n: BlockNumber) {
		let hash = self.block_hash(BlockId::Number(n)).unwrap();
		let mut header: BlockHeader = self.block_header(BlockId::Number(n)).unwrap().decode();
		header.set_parent_hash(H256::from(42));
		let mut rlp = RlpStream::new_list(3);
		rlp.append(&header);
		rlp.append_raw(&::rlp::NULL_RLP, 1);
		rlp.append_raw(&::rlp::NULL_RLP, 1);
		self.blocks.write().insert(hash, rlp.out());
	}

	/// TODO:
	pub fn block_hash_delta_minus(&mut self, delta: usize) -> H256 {
		let blocks_read = self.numbers.read();
		let index = blocks_read.len() - delta;
		blocks_read[&index].clone()
	}

	fn block_hash(&self, id: BlockId) -> Option<H256> {
		match id {
			BlockId::Hash(hash) => Some(hash),
			BlockId::Number(n) => self.numbers.read().get(&(n as usize)).cloned(),
			BlockId::Earliest => self.numbers.read().get(&0).cloned(),
			BlockId::Latest | BlockId::Pending => self.numbers.read().get(&(self.numbers.read().len() - 1)).cloned()
		}
	}

	/// Inserts a transaction with given gas price to miners transactions queue.
	pub fn insert_transaction_with_gas_price_to_queue(&self, gas_price: U256) -> H256 {
		let keypair = Random.generate().unwrap();
		let tx = Transaction {
			action: Action::Create,
			value: U256::from(100),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: gas_price,
			nonce: U256::zero()
		};
		let signed_tx = tx.sign(keypair.secret(), None);
		self.set_balance(signed_tx.sender(), 10_000_000_000_000_000_000u64.into());
		let hash = signed_tx.hash();
		hash
	}

	/// Inserts a transaction to miners transactions queue.
	pub fn insert_transaction_to_queue(&self) -> H256 {
		self.insert_transaction_with_gas_price_to_queue(U256::from(20_000_000_000u64))
	}

	/// Set reported history size.
	pub fn set_history(&self, h: Option<u64>) {
		*self.history.write() = h;
	}
}

pub fn get_temp_state_db() -> GuardedTempResult<StateDB> {
	let temp = RandomTempPath::new();
    let db = kvdb_memorydb.create(NUM_COLUMNS);
	let journal_db = journaldb::new(Arc::new(db), journaldb::Algorithm::EarlyMerge, COL_STATE);
	let state_db = StateDB::new(journal_db, 1024 * 1024);
	GuardedTempResult {
		_temp: temp,
		result: Some(state_db)
	}
}
