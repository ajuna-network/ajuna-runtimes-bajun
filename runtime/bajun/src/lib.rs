// Ajuna Node
// Copyright (C) 2022 BlogaTech AG

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#![allow(clippy::items_after_test_module)]
#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

mod assets;
mod gov;
mod proxy_type;
mod weights;
pub mod xcm_config;

use crate::gov::EnsureRootOrMoreThanHalfCouncil;
use cumulus_primitives_core::AggregateMessageOrigin;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use smallvec::smallvec;
use sp_api::impl_runtime_apis;
use sp_core::{crypto::KeyTypeId, ConstU64, Get, OpaqueMetadata};
use sp_runtime::{
	create_runtime_str, generic, impl_opaque_keys,
	traits::{AccountIdLookup, BlakeTwo256, Block as BlockT},
	transaction_validity::{TransactionSource, TransactionValidity},
	ApplyExtrinsicResult, ExtrinsicInclusionMode, MultiSignature,
};
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

use frame_support::{
	construct_runtime,
	dispatch::DispatchClass,
	genesis_builder_helper::{build_state, get_preset},
	migrations::{FailedMigrationHandler, FailedMigrationHandling, MigrationStatusHandler},
	pallet_prelude::ConstU32,
	parameter_types,
	traits::{
		fungible::HoldConsideration,
		tokens::{imbalance::ResolveTo, PayFromAccount, UnityAssetBalanceConversion},
		AsEnsureOriginWithArg, ConstBool, Contains, LinearStoragePrice,
	},
	weights::{
		constants::WEIGHT_REF_TIME_PER_SECOND, ConstantMultiplier, Weight, WeightToFeeCoefficient,
		WeightToFeeCoefficients, WeightToFeePolynomial,
	},
	PalletId,
};
use frame_system::{
	limits::{BlockLength, BlockWeights},
	pallet_prelude::BlockNumberFor,
	EnsureRoot, EnsureSigned, EnsureWithSuccess,
};
use pallet_identity::legacy::IdentityInfo;
use pallet_transaction_payment::FungibleAdapter;
use scale_info::TypeInfo;
pub use sp_consensus_aura::sr25519::AuthorityId as AuraId;
pub use sp_runtime::{MultiAddress, Perbill, Permill};

#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

// Polkadot imports
use polkadot_runtime_common::{BlockHashCount, SlowAdjustingFeeUpdate};

use weights::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight};

// XCM Imports
use staging_xcm::latest::prelude::BodyId;

use pallet_nfts::{AttributeNamespace, Call as NftsCall};
use parachains_common::{message_queue::NarrowOriginToSibling, BlockNumber, Hash, Header};
use sp_runtime::traits::{IdentifyAccount, IdentityLookup, Verify};

parameter_types! {
	pub const OneDay: BlockNumber = DAYS;
	pub const OneWeek: BlockNumber = 7 * DAYS;
	pub const TwoWeeks: BlockNumber = 14 * DAYS;
}

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// Alias to the public key used for this chain, actually a `MultiSigner`. Like the signature, this
/// also isn't a fixed size when encoded, as different cryptos have different size public keys.
pub type AccountPublic = <Signature as Verify>::Signer;

/// Identifier of a collection of NFTs.
pub type CollectionId = u32;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
	SingleBlockMigrations,
>;

/// Handles converting a weight scalar to a fee value, based on the scale and granularity of the
/// node's balance type.
///
/// This should typically create a mapping between the following ranges:
///   - `[0, MAXIMUM_BLOCK_WEIGHT]`
///   - `[Balance::min, Balance::max]`
///
/// Yet, it can be used for any other sort of change to weight-fee. Some examples being:
///   - Setting it to `0` will essentially disable the weight fee.
///   - Setting it to `1` will cause the literal `#[weight = x]` values to be charged.
pub struct WeightToFee;
impl WeightToFeePolynomial for WeightToFee {
	type Balance = Balance;
	fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
		// in Rococo, extrinsic base weight (smallest non-zero weight) is mapped to 1 MILLI_BAJU:
		// in our template, we map to 1/10 of that, or 1/10 MILLI_BAJU
		let p = MILLI_BAJU / 10;
		let q = 100 * Balance::from(ExtrinsicBaseWeight::get().ref_time());
		smallvec![WeightToFeeCoefficient {
			degree: 1,
			negative: false,
			coeff_frac: Perbill::from_rational(p % q, q),
			coeff_integer: p / q,
		}]
	}
}

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
	use super::*;
	use sp_runtime::{
		generic,
		traits::{BlakeTwo256, Hash as HashT},
	};

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;
	/// Opaque block header type.
	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	/// Opaque block type.
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;
	/// Opaque block hash type.
	pub type Hash = <BlakeTwo256 as HashT>::Output;
}

impl_opaque_keys! {
	pub struct SessionKeys {
		pub aura: Aura,
	}
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("bajun"),
	impl_name: create_runtime_str!("bajun"),
	authoring_version: 1,
	spec_version: 802,
	impl_version: 0,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	state_version: 1,
};

/// Blocks will be produced at a minimum duration defined by `SLOT_DURATION`.
/// `SLOT_DURATION` is picked up by `pallet_timestamp` which is in turn picked
/// up by `pallet_aura` to implement `fn slot_duration()`.
///
/// Change this to adjust the block time.
pub const MILLISECS_PER_BLOCK: u64 = 6_000;

// NOTE: Currently it is not possible to change the slot duration after the chain has started.
//       Attempting to do so will brick block production.
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// Unit = the base number of indivisible units for balances
pub const BAJU: Balance = 1_000_000_000_000;
pub const MILLI_BAJU: Balance = 1_000_000_000;
pub const MICRO_BAJU: Balance = 1_000_000;
pub const NANO_BAJU: Balance = 1_000;
pub const PICO_BAJU: Balance = 1;

/// The existential deposit. Set to 1/10 of the Connected Relay Chain.
pub const EXISTENTIAL_DEPOSIT: Balance = MILLI_BAJU;

/// We assume that ~5% of the block weight is consumed by `on_initialize` handlers. This is
/// used to limit the maximal weight of a single extrinsic.
const AVERAGE_ON_INITIALIZE_RATIO: Perbill = Perbill::from_percent(5);

/// We allow `Normal` extrinsics to fill up the block up to 75%, the rest can be used by
/// `Operational` extrinsics.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

/// We allow for 2s of a second of compute with a 6-second average block time.
const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
	WEIGHT_REF_TIME_PER_SECOND.saturating_mul(2),
	cumulus_primitives_core::relay_chain::MAX_POV_SIZE as u64,
);

/// Maximum number of blocks simultaneously accepted by the Runtime, not yet included into the
/// relay chain.
pub const UNINCLUDED_SEGMENT_CAPACITY: u32 = 3;
/// How many parachain blocks are processed by the relay chain per parent. Limits the number of
/// blocks authored per slot.
pub const BLOCK_PROCESSING_VELOCITY: u32 = 1;
/// Relay chain slot duration, in milliseconds.
pub const RELAY_CHAIN_SLOT_DURATION_MILLIS: u32 = 6000;

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;

	// This part is copied from Substrate's `bin/node/runtime/src/lib.rs`.
	//  The `RuntimeBlockLength` and `RuntimeBlockWeights` exist here because the
	// `DeletionWeightLimit` and `DeletionQueueDepth` depend on those to parameterize
	// the lazy contract deletion.
	pub RuntimeBlockLength: BlockLength =
		BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
	pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
		.base_block(BlockExecutionWeight::get())
		.for_class(DispatchClass::all(), |weights| {
			weights.base_extrinsic = ExtrinsicBaseWeight::get();
		})
		.for_class(DispatchClass::Normal, |weights| {
			weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT);
		})
		.for_class(DispatchClass::Operational, |weights| {
			weights.max_total = Some(MAXIMUM_BLOCK_WEIGHT);
			// Operational transactions have some extra reserved space, so that they
			// are included even if block reached `MAXIMUM_BLOCK_WEIGHT`.
			weights.reserved = Some(
				MAXIMUM_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT
			);
		})
		.avg_block_initialization(AVERAGE_ON_INITIALIZE_RATIO)
		.build_or_panic();
	pub const SS58Prefix: u16 = 1337;
}

// Allow the following extrinsics only.
pub struct BaseCallFilter;
impl Contains<RuntimeCall> for BaseCallFilter {
	fn contains(call: &RuntimeCall) -> bool {
		match call {
			RuntimeCall::Nft(NftsCall::set_attribute { namespace, .. })
				if namespace == &AttributeNamespace::CollectionOwner =>
				true,
			RuntimeCall::Nft(NftsCall::set_attribute { namespace, .. })
				if namespace != &AttributeNamespace::CollectionOwner =>
				false,
			_ => true,
		}
	}
}

impl frame_system::Config for Runtime {
	/// The ubiquitous event type.
	type RuntimeEvent = RuntimeEvent;
	/// The basic call filter to use in dispatchable.
	type BaseCallFilter = BaseCallFilter;
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = RuntimeBlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = RuntimeBlockLength;
	/// The ubiquitous origin type.
	type RuntimeOrigin = RuntimeOrigin;
	/// The aggregated dispatch type that is available for extrinsics.
	type RuntimeCall = RuntimeCall;
	type RuntimeTask = RuntimeTask;
	/// The Nonce value type
	type Nonce = Nonce;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = AccountIdLookup<AccountId, ()>;
	/// The Block provider type
	type Block = Block;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RocksDbWeight;
	/// Runtime version.
	type Version = Version;
	/// Converts a module to an index of this module in the runtime.
	type PalletInfo = PalletInfo;
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// What to do if a new account is created.
	type OnNewAccount = ();
	/// What to do if an account is fully reaped from the system.
	type OnKilledAccount = ();
	/// Weight information for the extrinsics of this pallet.
	type SystemWeightInfo = weights::frame_system::WeightInfo<Runtime>;
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	/// The action to take on a Runtime Upgrade
	type OnSetCode = cumulus_pallet_parachain_system::ParachainSetCode<Self>;
	type MaxConsumers = frame_support::traits::ConstU32<16>;
	// Note: Single block migrations are currently run in the classical way in the `Executive`
	// because try-runtime doesn't support the pallet-migrations yet.
	//
	// Once it is supported, we want to switch to the pallet-migrations, but we **must** ensure
	// that we remove the migrations from the `Executive` to prevent running the migrations twice.
	type SingleBlockMigrations = ();
	type MultiBlockMigrator = pallet_migrations::Pallet<Runtime>;
	type PreInherents = ();
	type PostInherents = ();
	type PostTransactions = ();
}

type SingleBlockMigrations = ();

#[cfg(not(feature = "runtime-benchmarks"))]
use mbm::MultiBlockMigrations;

#[cfg(not(feature = "runtime-benchmarks"))]
mod mbm {
	pub type MultiBlockMigrations = ();
}

parameter_types! {
	pub MbmServiceWeight: Weight = Perbill::from_percent(80) * RuntimeBlockWeights::get().max_block;
}

impl pallet_migrations::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	#[cfg(feature = "runtime-benchmarks")]
	type Migrations = pallet_migrations::mock_helpers::MockedMigrations;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type Migrations = MultiBlockMigrations;
	type CursorMaxLen = ConstU32<65_536>;
	type IdentifierMaxLen = ConstU32<256>;
	type MigrationStatusHandler = LoggerMigrationStatusHandler;
	type FailedMigrationHandler = UnstuckFailedMigration;
	type MaxServiceWeight = MbmServiceWeight;
	type WeightInfo = weights::pallet_migrations::WeightInfo<Runtime>;
}

/// Records all started and completed upgrades in `UpgradesStarted` and `UpgradesCompleted`.
pub struct LoggerMigrationStatusHandler;
impl MigrationStatusHandler for LoggerMigrationStatusHandler {
	fn started() {
		log::info!("MigrationStatusHandler started");
	}

	fn completed() {
		log::info!("MigrationStatusHandler completed");
	}
}

/// Records all failed upgrades in `UpgradesFailed`.
pub struct UnstuckFailedMigration;
impl FailedMigrationHandler for UnstuckFailedMigration {
	fn failed(migration: Option<u32>) -> FailedMigrationHandling {
		log::error!("FailedMigrationHandler failed at: {migration:?}");
		FailedMigrationHandling::ForceUnstuck
	}
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = weights::pallet_sudo::WeightInfo<Runtime>;
}

impl pallet_timestamp::Config for Runtime {
	/// A timestamp: milliseconds since the unix epoch.
	type Moment = u64;
	type OnTimestampSet = Aura;
	type MinimumPeriod = ConstU64<0>;
	type WeightInfo = weights::pallet_timestamp::WeightInfo<Runtime>;
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Aura>;
	type EventHandler = (CollatorSelection,);
}

parameter_types! {
	pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
	pub const MaxLocks: u32 = 50;
	pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = ();
	type WeightInfo = weights::pallet_balances::WeightInfo<Runtime>;
	type Balance = Balance;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type ReserveIdentifier = [u8; 8];
	type FreezeIdentifier = ();
	type MaxLocks = MaxLocks;
	type MaxReserves = MaxReserves;
	type MaxFreezes = ();
}

parameter_types! {
	/// Relay Chain `TransactionByteFee` / 10
	pub const TransactionByteFee: Balance = 10 * MICRO_BAJU;
	pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = FungibleAdapter<Balances, ResolveTo<TreasuryAccount, Balances>>;
	type WeightToFee = WeightToFee;
	type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
	type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Self>;
	type OperationalFeeMultiplier = OperationalFeeMultiplier;
}

parameter_types! {
	pub const TreasuryPalletId: PalletId = PalletId(*b"aj/trsry");
	pub const ZeroPercent: Permill = Permill::from_percent(0);
	pub const FivePercent: Permill = Permill::from_percent(5);
	pub const FiftyPercent: Permill = Permill::from_percent(50);
	pub const Fortnightly: BlockNumber = 14 * DAYS;
	pub const Weekly: BlockNumber = 7 * DAYS;
	pub const Daily: BlockNumber = DAYS;
	pub const CouncilMaxMembers: u32 = 100;
	pub MaxProposalWeight: Weight = Perbill::from_percent(50) * RuntimeBlockWeights::get().max_block;
}

parameter_types! {
	pub TreasuryAccount: AccountId = Treasury::account_id();
	pub const SpendPayoutPeriod: u32 = 6 * DAYS;
	pub const MaxBalance: Balance = Balance::MAX;
}

impl pallet_treasury::Config for Runtime {
	type Currency = Balances;
	type RejectOrigin = EnsureRootOrMoreThanHalfCouncil;
	type RuntimeEvent = RuntimeEvent;
	type SpendPeriod = OneWeek;
	type Burn = ZeroPercent;
	type PalletId = TreasuryPalletId;
	type BurnDestination = ();
	type WeightInfo = weights::pallet_treasury::WeightInfo<Runtime>;
	type SpendFunds = ();
	type MaxApprovals = frame_support::traits::ConstU32<100>;
	type SpendOrigin = EnsureWithSuccess<EnsureRoot<AccountId>, AccountId, MaxBalance>;
	type AssetKind = ();
	type Beneficiary = Self::AccountId;
	type BeneficiaryLookup = IdentityLookup<Self::Beneficiary>;
	type Paymaster = PayFromAccount<Balances, TreasuryAccount>;
	type BalanceConverter = UnityAssetBalanceConversion;
	type PayoutPeriod = SpendPayoutPeriod;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = ();
}

parameter_types! {
	pub const MinVestedTransfer: Balance = MILLI_BAJU;
}

impl orml_vesting::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type MinVestedTransfer = MinVestedTransfer;
	type VestedTransferOrigin = EnsureSigned<AccountId>;
	type WeightInfo = weights::orml_vesting::WeightInfo<Runtime>;
	type MaxVestingSchedules = frame_support::traits::ConstU32<100>;
	// We use the parachain block number instead of the relay chain provider
	// because our active schedules would get messed up if we switched to the relay
	// chain block number instead of the parachain one
	type BlockNumberProvider = System;
}

parameter_types! {
	pub const ReservedXcmpWeight: Weight = MAXIMUM_BLOCK_WEIGHT.saturating_div(4);
	pub const ReservedDmpWeight: Weight = MAXIMUM_BLOCK_WEIGHT.saturating_div(4);
	pub const RelayOrigin: AggregateMessageOrigin = AggregateMessageOrigin::Parent;
}

type ConsensusHook = cumulus_pallet_aura_ext::FixedVelocityConsensusHook<
	Runtime,
	RELAY_CHAIN_SLOT_DURATION_MILLIS,
	BLOCK_PROCESSING_VELOCITY,
	UNINCLUDED_SEGMENT_CAPACITY,
>;

impl cumulus_pallet_parachain_system::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnSystemEvent = ();
	type SelfParaId = staging_parachain_info::Pallet<Runtime>;
	type OutboundXcmpMessageSource = XcmpQueue;
	type DmpQueue = frame_support::traits::EnqueueWithOrigin<MessageQueue, RelayOrigin>;
	type ReservedDmpWeight = ReservedDmpWeight;
	type XcmpMessageHandler = XcmpQueue;
	type ReservedXcmpWeight = ReservedXcmpWeight;
	type CheckAssociatedRelayNumber =
		cumulus_pallet_parachain_system::RelayNumberMonotonicallyIncreases;
	type WeightInfo = weights::cumulus_pallet_parachain_system::WeightInfo<Runtime>;
	type ConsensusHook = ConsensusHook;
}

impl staging_parachain_info::Config for Runtime {}

impl cumulus_pallet_aura_ext::Config for Runtime {}

parameter_types! {
	pub MessageQueueServiceWeight: Weight = Perbill::from_percent(35) * RuntimeBlockWeights::get().max_block;
}

impl pallet_message_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::pallet_message_queue::WeightInfo<Runtime>;
	#[cfg(feature = "runtime-benchmarks")]
	type MessageProcessor = pallet_message_queue::mock_helpers::NoopMessageProcessor<
		cumulus_primitives_core::AggregateMessageOrigin,
	>;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type MessageProcessor = staging_xcm_builder::ProcessXcmMessage<
		AggregateMessageOrigin,
		staging_xcm_executor::XcmExecutor<xcm_config::XcmConfig>,
		RuntimeCall,
	>;
	type Size = u32;
	// The XCMP queue pallet is only ever able to handle the `Sibling(ParaId)` origin:
	type QueueChangeHandler = NarrowOriginToSibling<XcmpQueue>;
	type QueuePausedQuery = NarrowOriginToSibling<XcmpQueue>;
	type HeapSize = sp_core::ConstU32<{ 64 * 1024 }>;
	type MaxStale = sp_core::ConstU32<8>;
	type ServiceWeight = MessageQueueServiceWeight;
	type IdleMaxServiceWeight = ();
}

parameter_types! {
	pub const Period: u32 = 6 * HOURS;
	pub const Offset: u32 = 0;
	pub const MaxAuthorities: u32 = 100_000;
}

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	// we don't have stash and controller, thus we don't need the convert as well.
	type ValidatorIdOf = pallet_collator_selection::IdentityCollator;
	type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
	type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
	type SessionManager = CollatorSelection;
	// Essentially just Aura, but lets be pedantic.
	type SessionHandler = <SessionKeys as sp_runtime::traits::OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type WeightInfo = weights::pallet_session::WeightInfo<Runtime>;
}

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type MaxAuthorities = MaxAuthorities;
	type DisabledValidators = ();
	type AllowMultipleBlocksPerSlot = ConstBool<true>;
	type SlotDuration = ConstU64<SLOT_DURATION>;
}

parameter_types! {
	pub const PotId: PalletId = PalletId(*b"PotStake");
	pub const MaxCandidates: u32 = 1000;
	pub const MinEligibleCollators: u32 = 5;
	pub const SessionLength: BlockNumber = 6 * HOURS;
	pub const MaxInvulnerables: u32 = 100;
	pub const ExecutiveBody: BodyId = BodyId::Executive;
}

// We allow root only to execute privileged collator selection operations.
pub type CollatorSelectionUpdateOrigin = EnsureRoot<AccountId>;

impl pallet_collator_selection::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type UpdateOrigin = CollatorSelectionUpdateOrigin;
	type PotId = PotId;
	type MaxCandidates = MaxCandidates;
	type MinEligibleCollators = MinEligibleCollators;
	type MaxInvulnerables = MaxInvulnerables;
	// should be a multiple of session or things will get inconsistent
	type KickThreshold = Period;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	type ValidatorIdOf = pallet_collator_selection::IdentityCollator;
	type ValidatorRegistration = Session;
	type WeightInfo = weights::pallet_collator_selection::WeightInfo<Runtime>;
}

pub const fn deposit(items: u32, bytes: u32) -> Balance {
	items as Balance * 20 * BAJU + (bytes as Balance) * 1_000 * MICRO_BAJU
}

parameter_types! {
	/// One storage item; key size is 32; value is size 4+4+16+32 bytes = 56 bytes.
	pub const DepositBase: Balance = deposit(1, 88);
	/// Additional storage item size of 32 bytes.
	pub const DepositFactor: Balance = deposit(0, 32);
	pub const MaxSignatories: u16 = 100;
}

impl pallet_multisig::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type DepositBase = DepositBase;
	type DepositFactor = DepositFactor;
	type MaxSignatories = MaxSignatories;
	type WeightInfo = weights::pallet_multisig::WeightInfo<Runtime>;
}

impl pallet_utility::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type PalletsOrigin = OriginCaller;
	type WeightInfo = weights::pallet_utility::WeightInfo<Runtime>;
}

parameter_types! {
	pub const BasicDeposit: Balance = deposit(1, 258);
	pub const ByteDeposit: Balance = deposit(0, 66);
	pub const SubAccountDeposit: Balance = deposit(1, 53);
	pub const MaxSubAccounts: u32 = 100;
	pub const MaxAdditionalFields: u32 = 2;
	pub const MaxRegistrars: u32 = 20;
	pub const MaxSuffixLength: u32 = 7;
	pub const MaxUsernameLength: u32 = 32;
}

impl pallet_identity::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type BasicDeposit = BasicDeposit;
	type ByteDeposit = ByteDeposit;
	type SubAccountDeposit = SubAccountDeposit;
	type MaxSubAccounts = MaxSubAccounts;
	type IdentityInformation = IdentityInfo<MaxAdditionalFields>;
	type MaxRegistrars = MaxRegistrars;
	type Slashed = Treasury;
	type ForceOrigin = EnsureRoot<AccountId>;
	type RegistrarOrigin = EnsureRoot<AccountId>;
	type OffchainSignature = MultiSignature;
	type SigningPublicKey = AccountPublic;
	type UsernameAuthorityOrigin = EnsureRoot<Self::AccountId>;
	type PendingUsernameExpiration = ConstU32<100>;
	type MaxSuffixLength = MaxSuffixLength;
	type MaxUsernameLength = MaxUsernameLength;
	type WeightInfo = weights::pallet_identity::WeightInfo<Runtime>;
}

parameter_types! {
	// One storage item; key size 32, value size 8; .
	pub const ProxyDepositBase: Balance = deposit(1, 8);
	// Additional storage item size of 33 bytes.
	pub const ProxyDepositFactor: Balance = deposit(0, 33);
	pub const MaxProxies: u16 = 32;
	pub const AnnouncementDepositBase: Balance = deposit(1, 8);
	pub const AnnouncementDepositFactor: Balance = deposit(0, 66);
	pub const MaxPending: u16 = 32;
}

impl pallet_proxy::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ProxyType = proxy_type::ProxyType;
	type ProxyDepositBase = ProxyDepositBase;
	type ProxyDepositFactor = ProxyDepositFactor;
	type MaxProxies = MaxProxies;
	type WeightInfo = weights::pallet_proxy::WeightInfo<Runtime>;
	type MaxPending = MaxPending;
	type CallHasher = BlakeTwo256;
	type AnnouncementDepositBase = AnnouncementDepositBase;
	type AnnouncementDepositFactor = AnnouncementDepositFactor;
}

parameter_types! {
	pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) *
		RuntimeBlockWeights::get().max_block;
	pub const MaxScheduledPerBlock: u32 = 50;
	pub const NoPreimagePostponement: Option<u32> = Some(10);
}

impl pallet_scheduler::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeOrigin = RuntimeOrigin;
	type PalletsOrigin = OriginCaller;
	type RuntimeCall = RuntimeCall;
	type MaximumWeight = MaximumSchedulerWeight;
	type ScheduleOrigin = EnsureRoot<AccountId>;
	type OriginPrivilegeCmp = frame_support::traits::EqualPrivilegeOnly;
	type MaxScheduledPerBlock = MaxScheduledPerBlock;
	type WeightInfo = weights::pallet_scheduler::WeightInfo<Runtime>;
	type Preimages = Preimage;
}

parameter_types! {
	pub const PreimageBaseDeposit: Balance = deposit(2, 64);
	pub const PreimageByteDeposit: Balance = deposit(0, 1);
	pub const PreimageHoldReason: RuntimeHoldReason =
		RuntimeHoldReason::Preimage(pallet_preimage::HoldReason::Preimage);
}

impl pallet_preimage::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::pallet_preimage::WeightInfo<Runtime>;
	type Currency = Balances;
	type ManagerOrigin = EnsureRoot<AccountId>;
	type Consideration = HoldConsideration<
		AccountId,
		Balances,
		PreimageHoldReason,
		LinearStoragePrice<PreimageBaseDeposit, PreimageByteDeposit, Balance>,
	>;
}

impl pallet_insecure_randomness_collective_flip::Config for Runtime {}

parameter_types! {
	pub const AwesomeAvatarsPalletId: PalletId = PalletId(*b"aj/aaatr");
}

impl pallet_ajuna_awesome_avatars::Config for Runtime {
	type PalletId = AwesomeAvatarsPalletId;
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type Randomness = Randomness;
	type KeyLimit = KeyLimit;
	type ValueLimit = ValueLimit;
	type NftHandler = NftTransfer;
	type FeeChainMaxLength = AffiliateMaxLevel;
	type AffiliateHandler = AffiliatesAAA;
	type TournamentHandler = TournamentAAA;
	type WeightInfo = pallet_ajuna_awesome_avatars::weights::AjunaWeight<Runtime>;
}

parameter_types! {
	pub const CollectionDeposit: Balance = 100 * BAJU;
	pub const ItemDeposit: Balance = BAJU / 10;
	pub const StringLimit: u32 = 128;
	pub const MetadataDepositBase: Balance = deposit(1, 129);
	pub const AttributeDepositBase: Balance = deposit(1, 0);
	pub const DepositPerByte: Balance = deposit(0, 1);
	pub const ApprovalsLimit: u32 = 1;
	pub const ItemAttributesApprovalsLimit: u32 = 10;
	pub const MaxTips: u32 = 1;
	pub const MaxDeadlineDuration: u32 = 1;
	pub const MaxAttributesPerCall: u32 = 10;
	// NOTE: BaseCallFilter is used to filter unwanted extrinsic calls since disabling features
	// result in benchmark errors as extrinsics are disabled.
	pub NftFeatures: pallet_nfts::PalletFeatures = pallet_nfts::PalletFeatures::all_enabled();
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct ParameterGet<const N: u32>;

impl<const N: u32> Get<u32> for ParameterGet<N> {
	fn get() -> u32 {
		N
	}
}

pub type KeyLimit = ParameterGet<32>;
pub type ValueLimit = ParameterGet<64>;

impl pallet_nfts::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type CollectionId = CollectionId;
	type ItemId = Hash;
	type Currency = Balances;
	type ForceOrigin = EnsureRoot<AccountId>;
	type CreateOrigin = AsEnsureOriginWithArg<EnsureSigned<AccountId>>;
	type Locker = NftTransfer;
	type CollectionDeposit = CollectionDeposit;
	type ItemDeposit = ItemDeposit;
	type MetadataDepositBase = MetadataDepositBase;
	type AttributeDepositBase = AttributeDepositBase;
	type DepositPerByte = DepositPerByte;
	type StringLimit = StringLimit;
	type KeyLimit = KeyLimit;
	type ValueLimit = ValueLimit;
	type ApprovalsLimit = ApprovalsLimit;
	type ItemAttributesApprovalsLimit = ItemAttributesApprovalsLimit;
	type MaxTips = MaxTips;
	type MaxDeadlineDuration = MaxDeadlineDuration;
	type MaxAttributesPerCall = MaxAttributesPerCall;
	type Features = NftFeatures;
	type OffchainSignature = Signature;
	type OffchainPublic = AccountPublic;
	#[cfg(feature = "runtime-benchmarks")]
	type Helper = NftBenchmarkHelper;
	type WeightInfo = weights::pallet_nfts::WeightInfo<Runtime>;
}

parameter_types! {
	pub const NftTransferPalletId: PalletId = PalletId(*b"aj/nfttr");
}

impl pallet_ajuna_nft_transfer::Config for Runtime {
	type PalletId = NftTransferPalletId;
	type RuntimeEvent = RuntimeEvent;
	type CollectionId = CollectionId;
	type ItemId = Hash;
	type ItemConfig = pallet_nfts::ItemConfig;
	type KeyLimit = KeyLimit;
	type ValueLimit = ValueLimit;
	type NftHelper = Nft;
}

parameter_types! {
	pub const AffiliateMaxLevel: u32 = 2;
}

pub type AffiliatesInstanceAAA = pallet_ajuna_affiliates::Instance1;
impl pallet_ajuna_affiliates::Config<AffiliatesInstanceAAA> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuleIdentifier = pallet_ajuna_awesome_avatars::types::AffiliateMethods;
	type RuntimeRule = pallet_ajuna_awesome_avatars::FeePropagationOf<Runtime>;
	type AffiliateMaxLevel = AffiliateMaxLevel;
}

parameter_types! {
	pub const TournamentPalletId1: PalletId = PalletId(*b"aj/trmt1");
	pub const MinimumTournamentPhaseDuration: BlockNumber = 100;
}

type TournamentInstance1 = pallet_ajuna_tournament::Instance1;
impl pallet_ajuna_tournament::Config<TournamentInstance1> for Runtime {
	type PalletId = TournamentPalletId1;
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type SeasonId = pallet_ajuna_awesome_avatars::types::SeasonId;
	type EntityId = pallet_ajuna_awesome_avatars::AvatarIdOf<Runtime>;
	type RankedEntity = pallet_ajuna_awesome_avatars::types::Avatar<BlockNumberFor<Runtime>>;
	type MinimumTournamentPhaseDuration = MinimumTournamentPhaseDuration;
}

// Create the runtime by composing the FRAME pallets that were previously configured.
construct_runtime!(
	pub struct Runtime
	{
		// System support stuff.
		System: frame_system = 0,
		ParachainSystem: cumulus_pallet_parachain_system = 1,
		Timestamp: pallet_timestamp = 2,
		ParachainInfo: staging_parachain_info = 3,
		Multisig: pallet_multisig = 4,
		Utility: pallet_utility = 5,
		Identity: pallet_identity = 6,
		Proxy: pallet_proxy = 7,
		Scheduler: pallet_scheduler = 8,
		Preimage: pallet_preimage = 9,
		Migrations: pallet_migrations = 10,

		// Monetary stuff.
		Balances: pallet_balances = 15,
		TransactionPayment: pallet_transaction_payment = 16,
		Vesting: orml_vesting = 17,

		// Collator support. The order of these 4 are important and shall not change.
		Authorship: pallet_authorship = 20,
		CollatorSelection: pallet_collator_selection = 21,
		Session: pallet_session = 22,
		Aura: pallet_aura = 23,
		AuraExt: cumulus_pallet_aura_ext = 24,

		// XCM helpers.
		XcmpQueue: cumulus_pallet_xcmp_queue = 30,
		PolkadotXcm: pallet_xcm = 31,
		CumulusXcm: cumulus_pallet_xcm = 32,
		// DmpQueue: cumulus_pallet_dmp_queue = 33,
		MessageQueue: pallet_message_queue = 34,
		XTokens: orml_xtokens = 35,
		OrmlXcm: orml_xcm = 36,

		// Governance
		Sudo: pallet_sudo = 40,
		Treasury: pallet_treasury = 41,
		// type CouncilCollectiveInstance = pallet_collective::Instance2
		Council: pallet_collective::<Instance2> = 42,
		// type CouncilMembershipInstance = pallet_membership::Instance2;
		CouncilMembership: pallet_membership::<Instance2> = 43,
		// pub type TechnicalCommitteeInstance = pallet_collective::Instance1;
		TechnicalCommittee: pallet_collective::<Instance1> = 44,
		// type TechnicalCommitteeMembershipInstance = pallet_membership::Instance1;
		TechnicalCommitteeMembership: pallet_membership::<Instance1> = 45,
		Democracy: pallet_democracy = 46,

		// Indexes 50-59 should be reserved for our games.
		Randomness: pallet_insecure_randomness_collective_flip = 50,
		AwesomeAvatars: pallet_ajuna_awesome_avatars = 51,

		// Indexes 60-69 should be reserved for NFT related pallets
		Nft: pallet_nfts = 60,
		NftTransfer: pallet_ajuna_nft_transfer = 61,

		// Indexes 70-79 should be reserved for Affiliate instances
		AffiliatesAAA: pallet_ajuna_affiliates::<Instance1> = 70,

		// Indexes 80-89 should be reserved for Tournament instances
		TournamentAAA: pallet_ajuna_tournament::<Instance1> = 80,

		// Assets related stuff
		Assets: pallet_assets::<Instance1> = 90,
		AssetRegistry: pallet_asset_registry = 91,
	}
);

#[cfg(feature = "runtime-benchmarks")]
#[macro_use]
extern crate frame_benchmarking;

#[cfg(feature = "runtime-benchmarks")]
mod benches {
	define_benchmarks!(
		[cumulus_pallet_parachain_system, ParachainSystem]
		[cumulus_pallet_xcmp_queue, XcmpQueue]
		[frame_system, SystemBench::<Runtime>]
		[orml_vesting, OrmlVestingBench::<Runtime>]
		[pallet_balances, Balances]
		[pallet_collator_selection, CollatorSelection]
		[pallet_collective, Council]
		// [pallet_collective, TechnicalCommittee] // writes to the same file
		[pallet_democracy, Democracy]
		[pallet_identity, Identity]
		[pallet_membership, CouncilMembership]
		// [pallet_membership, TechnicalCommitteeMembership] // writes to the same file
		[pallet_message_queue, MessageQueue]
		[pallet_migrations, Migrations]
		[pallet_multisig, Multisig]
		[pallet_preimage, Preimage]
		[pallet_proxy, Proxy]
		[pallet_scheduler, Scheduler]
		[pallet_session, SessionBench::<Runtime>]
		[pallet_sudo, Sudo]
		[pallet_timestamp, Timestamp]
		// [pallet_treasury, Treasury] // treasury config is broken, needs fixes
		[pallet_utility, Utility]
		// [pallet_ajuna_awesome_avatars, AwesomeAvatarsBench::<Runtime>]
		 // Note: We have to update the path to the `WeightInfo` definition after
		 // running the benchmarks: `pallet_ajuna_awesome_avatars::migration::v6::WeightInfo`
		// [pallet_ajuna_awesome_avatars_mbm, AwesomeAvatars]
		[pallet_nfts, Nft]
	);
	// Use this section if you want to benchmark individual pallets
	// define_benchmarks!([orml_vesting, OrmlVestingBench::<Runtime>]);
}

#[cfg(feature = "runtime-benchmarks")]
pub struct NftBenchmarkHelper;
#[cfg(feature = "runtime-benchmarks")]
impl<CollectionId: From<u16>, ItemId: From<[u8; 32]>>
	pallet_nfts::BenchmarkHelper<CollectionId, ItemId, AccountPublic, AccountId, Signature>
	for NftBenchmarkHelper
{
	fn collection(i: u16) -> CollectionId {
		i.into()
	}
	fn item(i: u16) -> ItemId {
		let mut id = [0_u8; 32];
		let bytes = i.to_be_bytes();
		id[0] = bytes[0];
		id[1] = bytes[1];
		id.into()
	}

	fn signer() -> (sp_runtime::MultiSigner, sp_runtime::AccountId32) {
		let public = sp_io::crypto::sr25519_generate(0.into(), None);
		let account = sp_runtime::MultiSigner::Sr25519(public).into_account();
		(public.into(), account)
	}
	fn sign(signer: &sp_runtime::MultiSigner, message: &[u8]) -> sp_runtime::MultiSignature {
		sp_runtime::MultiSignature::Sr25519(
			sp_io::crypto::sr25519_sign(0.into(), &signer.clone().try_into().unwrap(), message)
				.unwrap(),
		)
	}
}

impl_runtime_apis! {
	impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(SLOT_DURATION)
		}

		fn authorities() -> Vec<AuraId> {
			pallet_aura::Authorities::<Runtime>::get().into_inner()
		}
	}

	impl cumulus_primitives_aura::AuraUnincludedSegmentApi<Block> for Runtime {
		fn can_build_upon(
			included_hash: <Block as BlockT>::Hash,
			slot: cumulus_primitives_aura::Slot,
		) -> bool {
			ConsensusHook::can_build_upon(included_hash, slot)
		}
	}

	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block)
		}

		fn initialize_block(header: &<Block as BlockT>::Header) -> ExtrinsicInclusionMode {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> sp_std::vec::Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: Block,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			SessionKeys::generate(seed)
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
		fn query_info(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment::FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}
		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl cumulus_primitives_core::CollectCollationInfo<Block> for Runtime {
		fn collect_collation_info(header: &<Block as BlockT>::Header) -> cumulus_primitives_core::CollationInfo {
			ParachainSystem::collect_collation_info(header)
		}
	}

	#[cfg(feature = "try-runtime")]
	impl frame_try_runtime::TryRuntime<Block> for Runtime {
		fn on_runtime_upgrade(checks: frame_try_runtime::UpgradeCheckSelect) -> (Weight, Weight) {
			let weight = Executive::try_runtime_upgrade(checks).unwrap();
			(weight, RuntimeBlockWeights::get().max_block)
		}

		fn execute_block(
			block: Block,
			state_root_check: bool,
			signature_check: bool,
			select: frame_try_runtime::TryStateSelect,
		) -> Weight {
			// NOTE: intentional unwrap: we don't want to propagate the error backwards, and want to
			// have a backtrace here.
			Executive::try_execute_block(block, state_root_check, signature_check, select).unwrap()
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			use frame_benchmarking::{Benchmarking, BenchmarkList};
			use frame_support::traits::StorageInfoTrait;
			use frame_system_benchmarking::Pallet as SystemBench;
			use cumulus_pallet_session_benchmarking::Pallet as SessionBench;
			// use pallet_ajuna_awesome_avatars_benchmarking::Pallet as AwesomeAvatarsBench;
			use orml_pallets_benchmarking::vesting::Pallet as OrmlVestingBench;

			let mut list = Vec::<BenchmarkList>::new();
			list_benchmarks!(list, extra);

			let storage_info = AllPalletsWithSystem::storage_info();
			(list, storage_info)
		}

		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig
		) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
			use frame_benchmarking::{BenchmarkError, Benchmarking, BenchmarkBatch};
			use sp_storage::TrackedStorageKey;

			use frame_system_benchmarking::Pallet as SystemBench;
			impl frame_system_benchmarking::Config for Runtime {
				fn setup_set_code_requirements(code: &sp_std::vec::Vec<u8>) -> Result<(), BenchmarkError> {
					ParachainSystem::initialize_for_set_code_benchmark(code.len() as u32);
					Ok(())
				}

				fn verify_set_code() {
					System::assert_last_event(cumulus_pallet_parachain_system::Event::<Runtime>::ValidationFunctionStored.into());
				}
			}

			use cumulus_pallet_session_benchmarking::Pallet as SessionBench;
			impl cumulus_pallet_session_benchmarking::Config for Runtime {}

			// use pallet_ajuna_awesome_avatars_benchmarking::Pallet as AwesomeAvatarsBench;
			// impl pallet_ajuna_awesome_avatars_benchmarking::Config for Runtime {}

			use orml_pallets_benchmarking::vesting::Pallet as OrmlVestingBench;
			impl orml_pallets_benchmarking::vesting::Config for Runtime {}

			let whitelist: Vec<TrackedStorageKey> = vec![
				// Block Number
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac").to_vec().into(),
				// Total Issuance
				hex_literal::hex!("c2261276cc9d1f8598ea4b6a74b15c2f57c875e4cff74148e4628f264b974c80").to_vec().into(),
				// Execution Phase
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef7ff553b5a9862a516939d82b3d3d8661a").to_vec().into(),
				// Event Count
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef70a98fdbe9ce6c55837576c60c7af3850").to_vec().into(),
				// System Events
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7").to_vec().into(),
			];

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);
			add_benchmarks!(params, batches);

			if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
			Ok(batches)
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_state::<RuntimeGenesisConfig>(config)
		}

		fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
			get_preset::<RuntimeGenesisConfig>(id, |_| None)
		}

		fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
			Default::default()
		}
	}
}

cumulus_pallet_parachain_system::register_validate_block! {
	Runtime = Runtime,
	BlockExecutor = cumulus_pallet_aura_ext::BlockExecutor::<Runtime, Executive>,
}
