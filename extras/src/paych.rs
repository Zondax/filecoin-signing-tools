use fvm_shared::address::Address;
use fvm_shared::bigint::{bigint_ser, BigInt};
use fvm_shared::clock::ChainEpoch;
use fvm_shared::encoding::{serde_bytes, RawBytes};
use fvm_shared::MethodNum;
use fvm_shared::crypto::signature::Signature;
use serde::{Deserialize, Serialize};
use fil_actor_paych::{
    ConstructorParams,
    SignedVoucher,
    ModVerifyParams,
    PaymentVerifyParams,
    UpdateChannelStateParams,
    Merge,
};

#[derive(Serialize, Deserialize)]
#[serde(remote = "ConstructorParams")]
pub struct ConstructorParamsAPI {
    pub from: Address,
    pub to: Address,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(remote = "SignedVoucher")]
pub struct SignedVoucherAPI {
    /// ChannelAddr is the address of the payment channel this signed voucher is valid for
    pub channel_addr: Address,
    /// Min epoch before which the voucher cannot be redeemed
    pub time_lock_min: ChainEpoch,
    /// Max epoch beyond which the voucher cannot be redeemed
    /// set to 0 means no timeout
    pub time_lock_max: ChainEpoch,
    /// (optional) Used by `to` to validate
    #[serde(with = "serde_bytes")]
    pub secret_pre_image: Vec<u8>,
    /// (optional) Specified by `from` to add a verification method to the voucher
    pub extra: Option<ModVerifyParams>,
    /// Specifies which lane the Voucher merges into (will be created if does not exist)
    pub lane: u64,
    /// Set by `from` to prevent redemption of stale vouchers on a lane
    pub nonce: u64,
    /// Amount voucher can be redeemed for
    #[serde(with = "bigint_ser")]
    pub amount: BigInt,
    /// (optional) Can extend channel min_settle_height if needed
    pub min_settle_height: ChainEpoch,

    /// (optional) Set of lanes to be merged into `lane`
    pub merges: Vec<Merge>,

    /// Sender's signature over the voucher (sign on none)
    pub signature: Option<Signature>,
}

/// Modular Verification method
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ModVerifyParams")]
pub struct ModVerifyParamsAPI {
    pub actor: Address,
    pub method: MethodNum,
    pub data: RawBytes,
}

/// Payment Verification parameters
#[derive(Serialize, Deserialize)]
#[serde(remote = "PaymentVerifyParams")]
pub struct PaymentVerifyParamsAPI {
    pub extra: RawBytes,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "UpdateChannelStateParams")]
pub struct UpdateChannelStateParamsAPI {
    pub sv: SignedVoucher,
    #[serde(with = "serde_bytes")]
    pub secret: Vec<u8>,
    // * proof removed in v2
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "Merge")]
pub struct MergeAPI {
    pub lane: u64,
    pub nonce: u64,
}