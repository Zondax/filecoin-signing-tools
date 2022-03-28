use fvm_shared::address::Address;
use fvm_shared::bigint::bigint_ser;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::MethodNum;
use fvm_shared::encoding::{serde_bytes, RawBytes};
use serde::{Deserialize, Serialize};
use fil_actor_multisig::{
    Transaction,
    ConstructorParams,
    ProposeParams,
    TxnIDParams,
    AddSignerParams,
    RemoveSignerParams,
    SwapSignerParams,
    ChangeNumApprovalsThresholdParams,
    LockBalanceParams,
    TxnID
};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(remote = "Transaction")]
pub struct TransactionAPI {
    pub to: Address,
    #[serde(with = "bigint_ser")]
    pub value: TokenAmount,
    pub method: MethodNum,
    pub params: RawBytes,

    pub approved: Vec<Address>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ConstructorParams")]
pub struct ConstructorParamsAPI {
    pub signers: Vec<Address>,
    pub num_approvals_threshold: u64,
    pub unlock_duration: ChainEpoch,
    pub start_epoch: ChainEpoch,
}

#[derive(Serialize, Deserialize)]
pub struct ConstructorParamsV1 {
    pub signers: Vec<Address>,
    pub num_approvals_threshold: i64,
    pub unlock_duration: ChainEpoch,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ProposeParams")]
pub struct ProposeParamsAPI {
    pub to: Address,
    #[serde(with = "bigint_ser")]
    pub value: TokenAmount,
    pub method: MethodNum,
    pub params: RawBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "TxnIDParams")]
pub struct TxnIDParamsAPI {
    pub id: TxnID,
    /// Optional hash of proposal to ensure an operation can only apply to a
    /// specific proposal.
    #[serde(with = "serde_bytes")]
    pub proposal_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "AddSignerParams")]
pub struct AddSignerParamsAPI {
    pub signer: Address,
    pub increase: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "RemoveSignerParams")]
pub struct RemoveSignerParamsAPI {
    pub signer: Address,
    pub decrease: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "SwapSignerParams")]
pub struct SwapSignerParamsAPI {
    pub from: Address,
    pub to: Address,
}

/// Propose method call parameters
#[derive(Serialize, Deserialize)]
#[serde(remote = "ChangeNumApprovalsThresholdParams")]
pub struct ChangeNumApprovalsThresholdParamsAPI {
    pub new_threshold: u64,
}

/// Lock balance call params.
#[derive(Serialize, Deserialize)]
#[serde(remote = "LockBalanceParams")]
pub struct LockBalanceParamsAPI {
    pub start_epoch: ChainEpoch,
    pub unlock_duration: ChainEpoch,
    #[serde(with = "bigint_ser")]
    pub amount: TokenAmount,
}