use cid::Cid;
use fil_actor_miner::CompactCommD;
use fil_actor_miner::{
    ApplyRewardParams, ChangeMultiaddrsParams, ChangePeerIDParams, ChangeWorkerAddressParams,
    CheckSectorProvenParams, CompactPartitionsParams, CompactSectorNumbersParams,
    ConfirmSectorProofsParams, DeclareFaultsParams, DeclareFaultsRecoveredParams,
    DeferredCronEventParams, DisputeWindowedPoStParams, ExpirationExtension,
    ExtendSectorExpirationParams, FaultDeclaration, MinerConstructorParams, PoStPartition,
    PreCommitSectorBatchParams, PreCommitSectorBatchParams2, PreCommitSectorParams,
    ProveCommitAggregateParams, ProveCommitSectorParams, ProveReplicaUpdatesParams,
    RecoveryDeclaration, ReplicaUpdate, ReportConsensusFaultParams, SectorPreCommitInfo,
    SubmitWindowedPoStParams, TerminateSectorsParams, TerminationDeclaration,
    WithdrawBalanceParams,
};
use fvm_ipld_bitfield::BitField;
use fvm_ipld_encoding::{serde_bytes, BytesDe};
use fvm_shared::address::Address;
use fvm_shared::bigint::bigint_ser;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::deal::DealID;
use fvm_shared::econ::TokenAmount;
use fvm_shared::randomness::Randomness;
use fvm_shared::sector::{
    PoStProof, RegisteredPoStProof, RegisteredSealProof, RegisteredUpdateProof, SectorNumber,
    StoragePower,
};
use fvm_shared::smooth::FilterEstimate;
use serde::{Deserialize, Serialize};

use super::json::address;
use super::json::serde_base64_vector;
use super::json::tokenamount;
use super::json::vec_address;

/// Storage miner actor constructor params are defined here so the power actor can send them to the init actor
/// to instantiate miners.
#[derive(Serialize, Deserialize)]
#[serde(remote = "MinerConstructorParams", rename_all = "PascalCase")]
pub struct MinerConstructorParamsAPI {
    #[serde(with = "address")]
    pub owner: Address,
    #[serde(with = "address")]
    pub worker: Address,
    #[serde(with = "vec_address")]
    pub control_addresses: Vec<Address>,
    pub window_post_proof_type: RegisteredPoStProof,
    #[serde(with = "serde_base64_vector")]
    pub peer_id: Vec<u8>,
    pub multi_addresses: Vec<BytesDe>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ChangeWorkerAddressParams", rename_all = "PascalCase")]
pub struct ChangeWorkerAddressParamsAPI {
    #[serde(with = "address")]
    pub new_worker: Address,
    #[serde(with = "vec_address")]
    pub new_control_addresses: Vec<Address>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ChangePeerIDParams", rename_all = "PascalCase")]
pub struct ChangePeerIDParamsAPI {
    #[serde(with = "serde_base64_vector")]
    pub new_id: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ChangeMultiaddrsParams", rename_all = "PascalCase")]
pub struct ChangeMultiaddrsParamsAPI {
    pub new_multi_addrs: Vec<BytesDe>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ConfirmSectorProofsParams", rename_all = "PascalCase")]
pub struct ConfirmSectorProofsParamsAPI {
    pub sectors: Vec<SectorNumber>,
    pub reward_smoothed: FilterEstimate,
    #[serde(with = "bigint_ser")]
    pub reward_baseline_power: StoragePower,
    pub quality_adj_power_smoothed: FilterEstimate,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "DeferredCronEventParams", rename_all = "PascalCase")]
pub struct DeferredCronEventParamsAPI {
    #[serde(with = "serde_bytes")]
    pub event_payload: Vec<u8>,
    pub reward_smoothed: FilterEstimate,
    pub quality_adj_power_smoothed: FilterEstimate,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "PoStPartition", rename_all = "PascalCase")]
pub struct PoStPartitionAPI {
    /// Partitions are numbered per-deadline, from zero.
    pub index: u64,
    /// Sectors skipped while proving that weren't already declared faulty.
    pub skipped: BitField,
}

/// Information submitted by a miner to provide a Window PoSt.
#[derive(Serialize, Deserialize)]
#[serde(remote = "SubmitWindowedPoStParams", rename_all = "PascalCase")]
pub struct SubmitWindowedPoStParamsAPI {
    /// The deadline index which the submission targets.
    pub deadline: u64,
    /// The partitions being proven.
    pub partitions: Vec<PoStPartition>,
    /// Array of proofs, one per distinct registered proof type present in the sectors being proven.
    /// In the usual case of a single proof type, this array will always have a single element (independent of number of partitions).
    pub proofs: Vec<PoStProof>,
    /// The epoch at which these proofs is being committed to a particular chain.
    pub chain_commit_epoch: ChainEpoch,
    /// The ticket randomness on the chain at the `chain_commit_epoch` on the chain this post is committed to.
    pub chain_commit_rand: Randomness,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ProveCommitSectorParams", rename_all = "PascalCase")]
pub struct ProveCommitSectorParamsAPI {
    pub sector_number: SectorNumber,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "CheckSectorProvenParams", rename_all = "PascalCase")]
pub struct CheckSectorProvenParamsAPI {
    pub sector_number: SectorNumber,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ExtendSectorExpirationParams", rename_all = "PascalCase")]
pub struct ExtendSectorExpirationParamsAPI {
    pub extensions: Vec<ExpirationExtension>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ExpirationExtension", rename_all = "PascalCase")]
pub struct ExpirationExtensionAPI {
    pub deadline: u64,
    pub partition: u64,
    pub sectors: BitField,
    pub new_expiration: ChainEpoch,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "TerminateSectorsParams", rename_all = "PascalCase")]
pub struct TerminateSectorsParamsAPI {
    pub terminations: Vec<TerminationDeclaration>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "TerminationDeclaration", rename_all = "PascalCase")]
pub struct TerminationDeclarationAPI {
    pub deadline: u64,
    pub partition: u64,
    pub sectors: BitField,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "DeclareFaultsParams", rename_all = "PascalCase")]
pub struct DeclareFaultsParamsAPI {
    pub faults: Vec<FaultDeclaration>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "FaultDeclaration", rename_all = "PascalCase")]
pub struct FaultDeclarationAPI {
    /// The deadline to which the faulty sectors are assigned, in range [0..WPoStPeriodDeadlines)
    pub deadline: u64,
    /// Partition index within the deadline containing the faulty sectors.
    pub partition: u64,
    /// Sectors in the partition being declared faulty.
    pub sectors: BitField,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "DeclareFaultsRecoveredParams", rename_all = "PascalCase")]
pub struct DeclareFaultsRecoveredParamsAPI {
    pub recoveries: Vec<RecoveryDeclaration>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "RecoveryDeclaration", rename_all = "PascalCase")]
pub struct RecoveryDeclarationAPI {
    /// The deadline to which the recovered sectors are assigned, in range [0..WPoStPeriodDeadlines)
    pub deadline: u64,
    /// Partition index within the deadline containing the recovered sectors.
    pub partition: u64,
    /// Sectors in the partition being declared recovered.
    pub sectors: BitField,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "CompactPartitionsParams", rename_all = "PascalCase")]
pub struct CompactPartitionsParamsAPI {
    pub deadline: u64,
    pub partitions: BitField,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "CompactSectorNumbersParams", rename_all = "PascalCase")]
pub struct CompactSectorNumbersParamsAPI {
    pub mask_sector_numbers: BitField,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ReportConsensusFaultParams", rename_all = "PascalCase")]
pub struct ReportConsensusFaultParamsAPI {
    #[serde(with = "serde_base64_vector")]
    pub header1: Vec<u8>,
    #[serde(with = "serde_base64_vector")]
    pub header2: Vec<u8>,
    #[serde(with = "serde_base64_vector")]
    pub header_extra: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "WithdrawBalanceParams", rename_all = "PascalCase")]
pub struct WithdrawBalanceParamsAPI {
    #[serde(with = "tokenamount")]
    pub amount_requested: TokenAmount,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(remote = "PreCommitSectorBatchParams", rename_all = "PascalCase")]
pub struct PreCommitSectorBatchParamsAPI {
    pub sectors: Vec<PreCommitSectorParams>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(remote = "PreCommitSectorBatchParams2", rename_all = "PascalCase")]
pub struct PreCommitSectorBatchParams2API {
    pub sectors: Vec<SectorPreCommitInfo>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(remote = "PreCommitSectorParams", rename_all = "PascalCase")]
pub struct PreCommitSectorParamsAPI {
    pub seal_proof: RegisteredSealProof,
    pub sector_number: SectorNumber,
    /// CommR
    pub sealed_cid: Cid,
    pub seal_rand_epoch: ChainEpoch,
    pub deal_ids: Vec<DealID>,
    pub expiration: ChainEpoch,
    /// Whether to replace a "committed capacity" no-deal sector (requires non-empty DealIDs)
    pub replace_capacity: bool,
    /// The committed capacity sector to replace, and its deadline/partition location
    pub replace_sector_deadline: u64,
    pub replace_sector_partition: u64,
    pub replace_sector_number: SectorNumber,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(remote = "SectorPreCommitInfo", rename_all = "PascalCase")]
pub struct SectorPreCommitInfoAPI {
    pub seal_proof: RegisteredSealProof,
    pub sector_number: SectorNumber,
    /// CommR
    pub sealed_cid: Cid,
    pub seal_rand_epoch: ChainEpoch,
    pub deal_ids: Vec<DealID>,
    pub expiration: ChainEpoch,
    /// CommD
    pub unsealed_cid: CompactCommD,
}

// * Added in v2 -- param was previously a big int.
#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "ApplyRewardParams", rename_all = "PascalCase")]
pub struct ApplyRewardParamsAPI {
    #[serde(with = "tokenamount")]
    pub reward: TokenAmount,
    #[serde(with = "tokenamount")]
    pub penalty: TokenAmount,
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(remote = "DisputeWindowedPoStParams", rename_all = "PascalCase")]
pub struct DisputeWindowedPoStParamsAPI {
    pub deadline: u64,
    pub post_index: u64, // only one is allowed at a time to avoid loading too many sector infos.
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "ProveCommitAggregateParams", rename_all = "PascalCase")]
pub struct ProveCommitAggregateParamsAPI {
    pub sector_numbers: BitField,
    #[serde(with = "serde_base64_vector")]
    pub aggregate_proof: Vec<u8>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ReplicaUpdate", rename_all = "PascalCase")]
pub struct ReplicaUpdateAPI {
    pub sector_number: SectorNumber,
    pub deadline: u64,
    pub partition: u64,
    pub new_sealed_cid: Cid,
    pub deals: Vec<DealID>,
    pub update_proof_type: RegisteredUpdateProof,
    #[serde(with = "serde_base64_vector")]
    pub replica_proof: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "ProveReplicaUpdatesParams", rename_all = "PascalCase")]
pub struct ProveReplicaUpdatesParamsAPI {
    pub updates: Vec<ReplicaUpdate>,
}
