#[allow(unused_imports)]
use ethabi;
#[allow(dead_code)]
const INTERNAL_ERR: &'static str = "`ethabi_derive` internal error";
#[doc = r" Contract"]
pub struct Operations {}
impl Default for Operations {
	fn default() -> Self {
		Operations {}
	}
}
impl Operations {}
pub mod functions {
	use ethabi;
	pub struct AddClient {
		function: ethabi::Function,
	}
	impl Default for AddClient {
		fn default() -> Self {
			AddClient {
				function: ethabi::Function {
					name: "addClient".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_owner".to_owned(),
							kind: ethabi::ParamType::Address,
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl AddClient {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Address>>(
			&self,
			client: T0,
			owner: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::Address(owner.into()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct Checksum {
		function: ethabi::Function,
	}
	impl Default for Checksum {
		fn default() -> Self {
			Checksum {
				function: ethabi::Function {
					name: "checksum".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_release".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_platform".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl Checksum {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Hash>, T2: Into<ethabi::Hash>>(
			&self,
			client: T0,
			release: T1,
			platform: T2,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::FixedBytes(release.into().to_vec()),
				ethabi::Token::FixedBytes(platform.into().to_vec()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Hash> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok({
				let mut result = [0u8; 32];
				let v = out.to_fixed_bytes().expect(super::INTERNAL_ERR);
				result.copy_from_slice(&v);
				result
			})
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Hash>,
			T2: Into<ethabi::Hash>,
		>(
			&self,
			client: T0,
			release: T1,
			platform: T2,
			call: F,
		) -> ethabi::Result<ethabi::Hash> {
			let encoded_input = self.input(client, release, platform);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct LatestInTrack {
		function: ethabi::Function,
	}
	impl Default for LatestInTrack {
		fn default() -> Self {
			LatestInTrack {
				function: ethabi::Function {
					name: "latestInTrack".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_track".to_owned(),
							kind: ethabi::ParamType::Uint(8usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl LatestInTrack {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Uint>>(
			&self,
			client: T0,
			track: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::Uint(track.into()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Hash> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok({
				let mut result = [0u8; 32];
				let v = out.to_fixed_bytes().expect(super::INTERNAL_ERR);
				result.copy_from_slice(&v);
				result
			})
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Uint>,
		>(
			&self,
			client: T0,
			track: T1,
			call: F,
		) -> ethabi::Result<ethabi::Hash> {
			let encoded_input = self.input(client, track);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct ResetClientOwner {
		function: ethabi::Function,
	}
	impl Default for ResetClientOwner {
		fn default() -> Self {
			ResetClientOwner {
				function: ethabi::Function {
					name: "resetClientOwner".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_newOwner".to_owned(),
							kind: ethabi::ParamType::Address,
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl ResetClientOwner {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Address>>(
			&self,
			client: T0,
			new_owner: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::Address(new_owner.into()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct RemoveClient {
		function: ethabi::Function,
	}
	impl Default for RemoveClient {
		fn default() -> Self {
			RemoveClient {
				function: ethabi::Function {
					name: "removeClient".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl RemoveClient {
		pub fn input<T0: Into<ethabi::Hash>>(&self, client: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::FixedBytes(client.into().to_vec())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct AddRelease {
		function: ethabi::Function,
	}
	impl Default for AddRelease {
		fn default() -> Self {
			AddRelease {
				function: ethabi::Function {
					name: "addRelease".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_release".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_forkBlock".to_owned(),
							kind: ethabi::ParamType::Uint(32usize),
						},
						ethabi::Param {
							name: "_track".to_owned(),
							kind: ethabi::ParamType::Uint(8usize),
						},
						ethabi::Param {
							name: "_semver".to_owned(),
							kind: ethabi::ParamType::Uint(24usize),
						},
						ethabi::Param {
							name: "_critical".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl AddRelease {
		pub fn input<
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Uint>,
			T2: Into<ethabi::Uint>,
			T3: Into<ethabi::Uint>,
			T4: Into<bool>,
		>(
			&self,
			release: T0,
			fork_block: T1,
			track: T2,
			semver: T3,
			critical: T4,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(release.into().to_vec()),
				ethabi::Token::Uint(fork_block.into()),
				ethabi::Token::Uint(track.into()),
				ethabi::Token::Uint(semver.into()),
				ethabi::Token::Bool(critical.into()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct Track {
		function: ethabi::Function,
	}
	impl Default for Track {
		fn default() -> Self {
			Track {
				function: ethabi::Function {
					name: "track".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_release".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Uint(8usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl Track {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Hash>>(
			&self,
			client: T0,
			release: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::FixedBytes(release.into().to_vec()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Uint> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok(out.to_uint().expect(super::INTERNAL_ERR))
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Hash>,
		>(
			&self,
			client: T0,
			release: T1,
			call: F,
		) -> ethabi::Result<ethabi::Uint> {
			let encoded_input = self.input(client, release);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct ProposedFork {
		function: ethabi::Function,
	}
	impl Default for ProposedFork {
		fn default() -> Self {
			ProposedFork {
				function: ethabi::Function {
					name: "proposedFork".to_owned(),
					inputs: vec![],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Uint(32usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl ProposedFork {
		pub fn input(&self) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Uint> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok(out.to_uint().expect(super::INTERNAL_ERR))
		}
		pub fn call<F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>>(
			&self,
			call: F,
		) -> ethabi::Result<ethabi::Uint> {
			let encoded_input = self.input();
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct GrandOwner {
		function: ethabi::Function,
	}
	impl Default for GrandOwner {
		fn default() -> Self {
			GrandOwner {
				function: ethabi::Function {
					name: "grandOwner".to_owned(),
					inputs: vec![],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Address,
						},
					],
					constant: true,
				},
			}
		}
	}
	impl GrandOwner {
		pub fn input(&self) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Address> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok(out.to_address().expect(super::INTERNAL_ERR))
		}
		pub fn call<F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>>(
			&self,
			call: F,
		) -> ethabi::Result<ethabi::Address> {
			let encoded_input = self.input();
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct SetOwner {
		function: ethabi::Function,
	}
	impl Default for SetOwner {
		fn default() -> Self {
			SetOwner {
				function: ethabi::Function {
					name: "setOwner".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_newOwner".to_owned(),
							kind: ethabi::ParamType::Address,
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl SetOwner {
		pub fn input<T0: Into<ethabi::Address>>(&self, new_owner: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::Address(new_owner.into())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct SetClientOwner {
		function: ethabi::Function,
	}
	impl Default for SetClientOwner {
		fn default() -> Self {
			SetClientOwner {
				function: ethabi::Function {
					name: "setClientOwner".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_newOwner".to_owned(),
							kind: ethabi::ParamType::Address,
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl SetClientOwner {
		pub fn input<T0: Into<ethabi::Address>>(&self, new_owner: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::Address(new_owner.into())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct SetClientRequired {
		function: ethabi::Function,
	}
	impl Default for SetClientRequired {
		fn default() -> Self {
			SetClientRequired {
				function: ethabi::Function {
					name: "setClientRequired".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_r".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl SetClientRequired {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<bool>>(
			&self,
			client: T0,
			r: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::Bool(r.into()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct ConfirmTransaction {
		function: ethabi::Function,
	}
	impl Default for ConfirmTransaction {
		fn default() -> Self {
			ConfirmTransaction {
				function: ethabi::Function {
					name: "confirmTransaction".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_txid".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "txSuccess".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
					],
					constant: false,
				},
			}
		}
	}
	impl ConfirmTransaction {
		pub fn input<T0: Into<ethabi::Hash>>(&self, txid: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::FixedBytes(txid.into().to_vec())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct Fork {
		function: ethabi::Function,
	}
	impl Default for Fork {
		fn default() -> Self {
			Fork {
				function: ethabi::Function {
					name: "fork".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Uint(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "name".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "spec".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "hard".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
						ethabi::Param {
							name: "ratified".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
						ethabi::Param {
							name: "requiredCount".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl Fork {
		pub fn input<T0: Into<ethabi::Uint>>(&self, param0: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::Uint(param0.into())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(
			&self,
			output: &[u8],
		) -> ethabi::Result<(ethabi::Hash, ethabi::Hash, bool, bool, ethabi::Uint)> {
			let mut out = self.function.decode_output(output)?.into_iter();
			Ok(({
				 let mut result = [0u8; 32];
				 let v = out.next()
				            .expect(super::INTERNAL_ERR)
				            .to_fixed_bytes()
				            .expect(super::INTERNAL_ERR);
				 result.copy_from_slice(&v);
				 result
				},
			 {
				 let mut result = [0u8; 32];
				 let v = out.next()
				            .expect(super::INTERNAL_ERR)
				            .to_fixed_bytes()
				            .expect(super::INTERNAL_ERR);
				 result.copy_from_slice(&v);
				 result
				},
			 out.next().expect(super::INTERNAL_ERR).to_bool().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_bool().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_uint().expect(super::INTERNAL_ERR)))
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Uint>,
		>(
			&self,
			param0: T0,
			call: F,
		) -> ethabi::Result<(ethabi::Hash, ethabi::Hash, bool, bool, ethabi::Uint)> {
			let encoded_input = self.input(param0);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct AddChecksum {
		function: ethabi::Function,
	}
	impl Default for AddChecksum {
		fn default() -> Self {
			AddChecksum {
				function: ethabi::Function {
					name: "addChecksum".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_release".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_platform".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_checksum".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl AddChecksum {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Hash>, T2: Into<ethabi::Hash>>(
			&self,
			release: T0,
			platform: T1,
			checksum: T2,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(release.into().to_vec()),
				ethabi::Token::FixedBytes(platform.into().to_vec()),
				ethabi::Token::FixedBytes(checksum.into().to_vec()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct LatestFork {
		function: ethabi::Function,
	}
	impl Default for LatestFork {
		fn default() -> Self {
			LatestFork {
				function: ethabi::Function {
					name: "latestFork".to_owned(),
					inputs: vec![],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Uint(32usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl LatestFork {
		pub fn input(&self) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Uint> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok(out.to_uint().expect(super::INTERNAL_ERR))
		}
		pub fn call<F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>>(
			&self,
			call: F,
		) -> ethabi::Result<ethabi::Uint> {
			let encoded_input = self.input();
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct AcceptFork {
		function: ethabi::Function,
	}
	impl Default for AcceptFork {
		fn default() -> Self {
			AcceptFork {
				function: ethabi::Function {
					name: "acceptFork".to_owned(),
					inputs: vec![],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl AcceptFork {
		pub fn input(&self) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct ProposeFork {
		function: ethabi::Function,
	}
	impl Default for ProposeFork {
		fn default() -> Self {
			ProposeFork {
				function: ethabi::Function {
					name: "proposeFork".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_number".to_owned(),
							kind: ethabi::ParamType::Uint(32usize),
						},
						ethabi::Param {
							name: "_name".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_hard".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
						ethabi::Param {
							name: "_spec".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl ProposeFork {
		pub fn input<
			T0: Into<ethabi::Uint>,
			T1: Into<ethabi::Hash>,
			T2: Into<bool>,
			T3: Into<ethabi::Hash>,
		>(
			&self,
			number: T0,
			name: T1,
			hard: T2,
			spec: T3,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::Uint(number.into()),
				ethabi::Token::FixedBytes(name.into().to_vec()),
				ethabi::Token::Bool(hard.into()),
				ethabi::Token::FixedBytes(spec.into().to_vec()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct Build {
		function: ethabi::Function,
	}
	impl Default for Build {
		fn default() -> Self {
			Build {
				function: ethabi::Function {
					name: "build".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_checksum".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "o_release".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "o_platform".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl Build {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Hash>>(
			&self,
			client: T0,
			checksum: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::FixedBytes(checksum.into().to_vec()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<(ethabi::Hash, ethabi::Hash)> {
			let mut out = self.function.decode_output(output)?.into_iter();
			Ok(({
				 let mut result = [0u8; 32];
				 let v = out.next()
				            .expect(super::INTERNAL_ERR)
				            .to_fixed_bytes()
				            .expect(super::INTERNAL_ERR);
				 result.copy_from_slice(&v);
				 result
				},
			 {
				 let mut result = [0u8; 32];
				 let v = out.next()
				            .expect(super::INTERNAL_ERR)
				            .to_fixed_bytes()
				            .expect(super::INTERNAL_ERR);
				 result.copy_from_slice(&v);
				 result
				}))
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Hash>,
		>(
			&self,
			client: T0,
			checksum: T1,
			call: F,
		) -> ethabi::Result<(ethabi::Hash, ethabi::Hash)> {
			let encoded_input = self.input(client, checksum);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct ProposeTransaction {
		function: ethabi::Function,
	}
	impl Default for ProposeTransaction {
		fn default() -> Self {
			ProposeTransaction {
				function: ethabi::Function {
					name: "proposeTransaction".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_txid".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_to".to_owned(),
							kind: ethabi::ParamType::Address,
						},
						ethabi::Param {
							name: "_data".to_owned(),
							kind: ethabi::ParamType::Address,
						},
						ethabi::Param {
							name: "_value".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
						ethabi::Param {
							name: "_gas".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "txSuccess".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
					],
					constant: false,
				},
			}
		}
	}
	impl ProposeTransaction {
		pub fn input<
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Address>,
			T2: Into<ethabi::Bytes>,
			T3: Into<ethabi::Uint>,
			T4: Into<ethabi::Uint>,
		>(
			&self,
			txid: T0,
			to: T1,
			data: T2,
			value: T3,
			gas: T4,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(txid.into().to_vec()),
				ethabi::Token::Address(to.into()),
				ethabi::Token::Bytes(data.into()),
				ethabi::Token::Uint(value.into()),
				ethabi::Token::Uint(gas.into()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct ClientsRequired {
		function: ethabi::Function,
	}
	impl Default for ClientsRequired {
		fn default() -> Self {
			ClientsRequired {
				function: ethabi::Function {
					name: "clientsRequired".to_owned(),
					inputs: vec![],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Uint(32usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl ClientsRequired {
		pub fn input(&self) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Uint> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok(out.to_uint().expect(super::INTERNAL_ERR))
		}
		pub fn call<F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>>(
			&self,
			call: F,
		) -> ethabi::Result<ethabi::Uint> {
			let encoded_input = self.input();
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct RejectFork {
		function: ethabi::Function,
	}
	impl Default for RejectFork {
		fn default() -> Self {
			RejectFork {
				function: ethabi::Function {
					name: "rejectFork".to_owned(),
					inputs: vec![],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl RejectFork {
		pub fn input(&self) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct ClientOwner {
		function: ethabi::Function,
	}
	impl Default for ClientOwner {
		fn default() -> Self {
			ClientOwner {
				function: ethabi::Function {
					name: "clientOwner".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Address,
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl ClientOwner {
		pub fn input<T0: Into<ethabi::Address>>(&self, param0: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::Address(param0.into())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<ethabi::Hash> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok({
				let mut result = [0u8; 32];
				let v = out.to_fixed_bytes().expect(super::INTERNAL_ERR);
				result.copy_from_slice(&v);
				result
			})
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Address>,
		>(
			&self,
			param0: T0,
			call: F,
		) -> ethabi::Result<ethabi::Hash> {
			let encoded_input = self.input(param0);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct Release {
		function: ethabi::Function,
	}
	impl Default for Release {
		fn default() -> Self {
			Release {
				function: ethabi::Function {
					name: "release".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_release".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "o_forkBlock".to_owned(),
							kind: ethabi::ParamType::Uint(32usize),
						},
						ethabi::Param {
							name: "o_track".to_owned(),
							kind: ethabi::ParamType::Uint(8usize),
						},
						ethabi::Param {
							name: "o_semver".to_owned(),
							kind: ethabi::ParamType::Uint(24usize),
						},
						ethabi::Param {
							name: "o_critical".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
					],
					constant: true,
				},
			}
		}
	}
	impl Release {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Hash>>(
			&self,
			client: T0,
			release: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::FixedBytes(release.into().to_vec()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(
			&self,
			output: &[u8],
		) -> ethabi::Result<(ethabi::Uint, ethabi::Uint, ethabi::Uint, bool)> {
			let mut out = self.function.decode_output(output)?.into_iter();
			Ok((out.next().expect(super::INTERNAL_ERR).to_uint().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_uint().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_uint().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_bool().expect(super::INTERNAL_ERR)))
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Hash>,
		>(
			&self,
			client: T0,
			release: T1,
			call: F,
		) -> ethabi::Result<(ethabi::Uint, ethabi::Uint, ethabi::Uint, bool)> {
			let encoded_input = self.input(client, release);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct RejectTransaction {
		function: ethabi::Function,
	}
	impl Default for RejectTransaction {
		fn default() -> Self {
			RejectTransaction {
				function: ethabi::Function {
					name: "rejectTransaction".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_txid".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![],
					constant: false,
				},
			}
		}
	}
	impl RejectTransaction {
		pub fn input<T0: Into<ethabi::Hash>>(&self, txid: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::FixedBytes(txid.into().to_vec())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
	}
	pub struct IsLatest {
		function: ethabi::Function,
	}
	impl Default for IsLatest {
		fn default() -> Self {
			IsLatest {
				function: ethabi::Function {
					name: "isLatest".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "_client".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
						ethabi::Param {
							name: "_release".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
					],
					constant: true,
				},
			}
		}
	}
	impl IsLatest {
		pub fn input<T0: Into<ethabi::Hash>, T1: Into<ethabi::Hash>>(
			&self,
			client: T0,
			release: T1,
		) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![
				ethabi::Token::FixedBytes(client.into().to_vec()),
				ethabi::Token::FixedBytes(release.into().to_vec()),
			];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<bool> {
			let out =
				self.function.decode_output(output)?.into_iter().next().expect(super::INTERNAL_ERR);
			Ok(out.to_bool().expect(super::INTERNAL_ERR))
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
			T1: Into<ethabi::Hash>,
		>(
			&self,
			client: T0,
			release: T1,
			call: F,
		) -> ethabi::Result<bool> {
			let encoded_input = self.input(client, release);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct Client {
		function: ethabi::Function,
	}
	impl Default for Client {
		fn default() -> Self {
			Client {
				function: ethabi::Function {
					name: "client".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "owner".to_owned(),
							kind: ethabi::ParamType::Address,
						},
						ethabi::Param {
							name: "required".to_owned(),
							kind: ethabi::ParamType::Bool,
						},
					],
					constant: true,
				},
			}
		}
	}
	impl Client {
		pub fn input<T0: Into<ethabi::Hash>>(&self, param0: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::FixedBytes(param0.into().to_vec())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(&self, output: &[u8]) -> ethabi::Result<(ethabi::Address, bool)> {
			let mut out = self.function.decode_output(output)?.into_iter();
			Ok((out.next().expect(super::INTERNAL_ERR).to_address().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_bool().expect(super::INTERNAL_ERR)))
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
		>(
			&self,
			param0: T0,
			call: F,
		) -> ethabi::Result<(ethabi::Address, bool)> {
			let encoded_input = self.input(param0);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
	pub struct Proxy {
		function: ethabi::Function,
	}
	impl Default for Proxy {
		fn default() -> Self {
			Proxy {
				function: ethabi::Function {
					name: "proxy".to_owned(),
					inputs: vec![
						ethabi::Param {
							name: "".to_owned(),
							kind: ethabi::ParamType::FixedBytes(32usize),
						},
					],
					outputs: vec![
						ethabi::Param {
							name: "requiredCount".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
						ethabi::Param {
							name: "to".to_owned(),
							kind: ethabi::ParamType::Address,
						},
						ethabi::Param {
							name: "data".to_owned(),
							kind: ethabi::ParamType::Address,
						},
						ethabi::Param {
							name: "value".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
						ethabi::Param {
							name: "gas".to_owned(),
							kind: ethabi::ParamType::Uint(256usize),
						},
					],
					constant: true,
				},
			}
		}
	}
	impl Proxy {
		pub fn input<T0: Into<ethabi::Hash>>(&self, param0: T0) -> ethabi::Bytes {
			let v: Vec<ethabi::Token> = vec![ethabi::Token::FixedBytes(param0.into().to_vec())];
			self.function.encode_input(&v).expect(super::INTERNAL_ERR)
		}
		pub fn output(
			&self,
			output: &[u8],
		) -> ethabi::Result<
			(ethabi::Uint,
			 ethabi::Address,
			 ethabi::Bytes,
			 ethabi::Uint,
			 ethabi::Uint),
		> {
			let mut out = self.function.decode_output(output)?.into_iter();
			Ok((out.next().expect(super::INTERNAL_ERR).to_uint().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_address().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_bytes().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_uint().expect(super::INTERNAL_ERR),
			 out.next().expect(super::INTERNAL_ERR).to_uint().expect(super::INTERNAL_ERR)))
		}
		pub fn call<
			F: FnOnce(ethabi::Bytes) -> ethabi::Result<ethabi::Bytes>,
			T0: Into<ethabi::Hash>,
		>(
			&self,
			param0: T0,
			call: F,
		) -> ethabi::Result<
			(ethabi::Uint,
			 ethabi::Address,
			 ethabi::Bytes,
			 ethabi::Uint,
			 ethabi::Uint),
		> {
			let encoded_input = self.input(param0);
			call(encoded_input).and_then(|encoded_output| self.output(&encoded_output))
		}
	}
}
pub struct OperationsFunctions {}
impl OperationsFunctions {
	pub fn add_client(&self) -> functions::AddClient {
		functions::AddClient::default()
	}
	pub fn checksum(&self) -> functions::Checksum {
		functions::Checksum::default()
	}
	pub fn latest_in_track(&self) -> functions::LatestInTrack {
		functions::LatestInTrack::default()
	}
	pub fn reset_client_owner(&self) -> functions::ResetClientOwner {
		functions::ResetClientOwner::default()
	}
	pub fn remove_client(&self) -> functions::RemoveClient {
		functions::RemoveClient::default()
	}
	pub fn add_release(&self) -> functions::AddRelease {
		functions::AddRelease::default()
	}
	pub fn track(&self) -> functions::Track {
		functions::Track::default()
	}
	pub fn proposed_fork(&self) -> functions::ProposedFork {
		functions::ProposedFork::default()
	}
	pub fn grand_owner(&self) -> functions::GrandOwner {
		functions::GrandOwner::default()
	}
	pub fn set_owner(&self) -> functions::SetOwner {
		functions::SetOwner::default()
	}
	pub fn set_client_owner(&self) -> functions::SetClientOwner {
		functions::SetClientOwner::default()
	}
	pub fn set_client_required(&self) -> functions::SetClientRequired {
		functions::SetClientRequired::default()
	}
	pub fn confirm_transaction(&self) -> functions::ConfirmTransaction {
		functions::ConfirmTransaction::default()
	}
	pub fn fork(&self) -> functions::Fork {
		functions::Fork::default()
	}
	pub fn add_checksum(&self) -> functions::AddChecksum {
		functions::AddChecksum::default()
	}
	pub fn latest_fork(&self) -> functions::LatestFork {
		functions::LatestFork::default()
	}
	pub fn accept_fork(&self) -> functions::AcceptFork {
		functions::AcceptFork::default()
	}
	pub fn propose_fork(&self) -> functions::ProposeFork {
		functions::ProposeFork::default()
	}
	pub fn build(&self) -> functions::Build {
		functions::Build::default()
	}
	pub fn propose_transaction(&self) -> functions::ProposeTransaction {
		functions::ProposeTransaction::default()
	}
	pub fn clients_required(&self) -> functions::ClientsRequired {
		functions::ClientsRequired::default()
	}
	pub fn reject_fork(&self) -> functions::RejectFork {
		functions::RejectFork::default()
	}
	pub fn client_owner(&self) -> functions::ClientOwner {
		functions::ClientOwner::default()
	}
	pub fn release(&self) -> functions::Release {
		functions::Release::default()
	}
	pub fn reject_transaction(&self) -> functions::RejectTransaction {
		functions::RejectTransaction::default()
	}
	pub fn is_latest(&self) -> functions::IsLatest {
		functions::IsLatest::default()
	}
	pub fn client(&self) -> functions::Client {
		functions::Client::default()
	}
	pub fn proxy(&self) -> functions::Proxy {
		functions::Proxy::default()
	}
}
impl Operations {
	pub fn functions(&self) -> OperationsFunctions {
		OperationsFunctions {}
	}
}
