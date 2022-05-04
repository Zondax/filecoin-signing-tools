use fil_actor_multisig::{
    AddSignerParams, ChangeNumApprovalsThresholdParams, ConstructorParams, LockBalanceParams,
    ProposeParams, RemoveSignerParams, SwapSignerParams, Transaction, TxnID, TxnIDParams,
};
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::MethodNum;
use serde::{Deserialize, Serialize};

use super::json::address;
use super::json::rawbytes;
use super::json::serde_base64_vector;
use super::json::tokenamount;
use super::json::vec_address;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(remote = "Transaction", rename_all = "PascalCase")]
pub struct TransactionAPI {
    #[serde(with = "address")]
    pub to: Address,
    #[serde(with = "tokenamount")]
    pub value: TokenAmount,
    pub method: MethodNum,
    #[serde(with = "rawbytes")]
    pub params: RawBytes,
    #[serde(with = "vec_address")]
    pub approved: Vec<Address>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ConstructorParams", rename_all = "PascalCase")]
pub struct ConstructorParamsAPI {
    #[serde(with = "vec_address")]
    pub signers: Vec<Address>,
    pub num_approvals_threshold: u64,
    pub unlock_duration: ChainEpoch,
    pub start_epoch: ChainEpoch,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConstructorParamsV1 {
    #[serde(with = "vec_address")]
    pub signers: Vec<Address>,
    pub num_approvals_threshold: i64,
    pub unlock_duration: ChainEpoch,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ProposeParams", rename_all = "PascalCase")]
pub struct ProposeParamsAPI {
    #[serde(with = "address")]
    pub to: Address,
    #[serde(with = "tokenamount")]
    pub value: TokenAmount,
    pub method: MethodNum,
    #[serde(with = "rawbytes")]
    pub params: RawBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "TxnIDParams", rename_all = "PascalCase")]
pub struct TxnIDParamsAPI {
    #[serde(alias = "ID")]
    pub id: TxnID,
    /// Optional hash of proposal to ensure an operation can only apply to a
    /// specific proposal.
    #[serde(with = "serde_base64_vector")]
    pub proposal_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "AddSignerParams", rename_all = "PascalCase")]
pub struct AddSignerParamsAPI {
    #[serde(with = "address")]
    pub signer: Address,
    pub increase: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "RemoveSignerParams", rename_all = "PascalCase")]
pub struct RemoveSignerParamsAPI {
    #[serde(with = "address")]
    pub signer: Address,
    pub decrease: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "SwapSignerParams", rename_all = "PascalCase")]
pub struct SwapSignerParamsAPI {
    #[serde(with = "address")]
    pub from: Address,
    #[serde(with = "address")]
    pub to: Address,
}

/// Propose method call parameters
#[derive(Serialize, Deserialize)]
#[serde(
    remote = "ChangeNumApprovalsThresholdParams",
    rename_all = "PascalCase"
)]
pub struct ChangeNumApprovalsThresholdParamsAPI {
    // Support typo to avoid breaking dev implementation
    #[serde(alias = "NewTreshold")]
    pub new_threshold: u64,
}

/// Lock balance call params.
#[derive(Serialize, Deserialize)]
#[serde(remote = "LockBalanceParams", rename_all = "PascalCase")]
pub struct LockBalanceParamsAPI {
    pub start_epoch: ChainEpoch,
    pub unlock_duration: ChainEpoch,
    #[serde(with = "tokenamount")]
    pub amount: TokenAmount,
}
