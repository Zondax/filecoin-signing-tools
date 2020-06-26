use forest_address::Address;
use clock::ChainEpoch;
use forest_encoding::tuple::*;
use num_bigint::biguint_ser;
use serde::{Deserialize, Serialize};
use forest_vm::{MethodNum, Serialized, TokenAmount, METHOD_CONSTRUCTOR};
use forest_cid::Cid;
use lazy_static::lazy_static;

/// Exec Params
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ExecParams {
    pub code_cid: Cid,
    pub constructor_params: Serialized,
}

/// Transaction ID type
// TODO change to uvarint encoding
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TxnID(pub i64);

/// Transaction type used in multisig actor
#[derive(Clone, PartialEq, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct Transaction {
    pub to: Address,
    #[serde(with = "biguint_ser")]
    pub value: TokenAmount,
    pub method: MethodNum,
    pub params: Serialized,

    pub approved: Vec<Address>,
}

/// Constructor parameters for multisig actor
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    pub signers: Vec<Address>,
    pub num_approvals_threshold: i64,
    pub unlock_duration: ChainEpoch,
}

/// Propose method call parameters
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ProposeParams {
    pub to: Address,
    #[serde(with = "biguint_ser")]
    pub value: TokenAmount,
    pub method: MethodNum,
    pub params: Serialized,
}

/// Propose method call parameters
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct TxnIDParams {
    pub id: TxnID,
    pub proposal_hash: [u8; 32],
}

/// Add signer params
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct AddSignerParams {
    pub signer: Address,
    pub increase: bool,
}

/// Remove signer params
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct RemoveSignerParams {
    pub signer: Address,
    pub decrease: bool,
}

/// Swap signer multisig method params
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct SwapSignerParams {
    pub from: Address,
    pub to: Address,
}

/// Propose method call parameters
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ChangeNumApprovalsThresholdParams {
    pub new_threshold: i64,
}

/// Multisig actor methods available
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    Propose = 2,
    Approve = 3,
    Cancel = 4,
    // TODO verify on finished spec this not needed
    // ClearCompleted = 5,
    AddSigner = 6,
    RemoveSigner = 7,
    SwapSigner = 8,
    ChangeNumApprovalsThreshold = 9,
}

lazy_static! {
    pub static ref SYSTEM_ACTOR_ADDR: Address         = Address::new_id(0);
    pub static ref INIT_ACTOR_ADDR: Address           = Address::new_id(1);
    pub static ref REWARD_ACTOR_ADDR: Address         = Address::new_id(2);
    pub static ref CRON_ACTOR_ADDR: Address           = Address::new_id(3);
    pub static ref STORAGE_POWER_ACTOR_ADDR: Address  = Address::new_id(4);
    pub static ref STORAGE_MARKET_ACTOR_ADDR: Address = Address::new_id(5);
    pub static ref VERIFIED_REGISTRY_ACTOR_ADDR: Address = Address::new_id(6);

    // Distinguished AccountActor that is the destination of all burnt funds.
    pub static ref BURNT_FUNDS_ACTOR_ADDR: Address    = Address::new_id(99);
}
