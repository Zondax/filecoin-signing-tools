use fil_actor_paych::{
    ConstructorParams, Merge, ModVerifyParams, PaymentVerifyParams, SignedVoucher,
    UpdateChannelStateParams,
};
use fvm_ipld_encoding::{serde_bytes, RawBytes};
use fvm_shared::address::Address;
use fvm_shared::bigint::{bigint_ser, BigInt};
use fvm_shared::clock::ChainEpoch;
use fvm_shared::crypto::signature::Signature;
use fvm_shared::MethodNum;
use serde::{Deserialize, Serialize};

use super::json::address;
use super::json::rawbytes;
use super::json::bigint;
use super::json::serde_base64_vector;

#[derive(Serialize, Deserialize)]
#[serde(remote = "ConstructorParams", rename_all = "PascalCase")]
pub struct ConstructorParamsAPI {
    #[serde(with = "address")]
    pub from: Address,
    #[serde(with = "address")]
    pub to: Address,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(remote = "SignedVoucher", rename_all = "PascalCase")]
pub struct SignedVoucherAPI {
    #[serde(with = "address")]
    pub channel_addr: Address,
    pub time_lock_min: ChainEpoch,
    pub time_lock_max: ChainEpoch,
    #[serde(with = "serde_base64_vector")]
    pub secret_pre_image: Vec<u8>,
    pub extra: Option<ModVerifyParams>,
    pub lane: u64,
    pub nonce: u64,
    #[serde(with = "bigint")]
    pub amount: BigInt,
    pub min_settle_height: ChainEpoch,
    pub merges: Vec<Merge>,
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(remote = "ModVerifyParams", rename_all = "PascalCase")]
pub struct ModVerifyParamsAPI {
    #[serde(with = "address")]
    pub actor: Address,
    pub method: MethodNum,
    #[serde(with = "rawbytes")]
    pub data: RawBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "PaymentVerifyParams", rename_all = "PascalCase")]
pub struct PaymentVerifyParamsAPI {
    #[serde(with = "rawbytes")]
    pub extra: RawBytes,
    #[serde(with = "serde_base64_vector")]
    pub proof: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "UpdateChannelStateParams", rename_all = "PascalCase")]
pub struct UpdateChannelStateParamsAPI {
    pub sv: SignedVoucher,
    #[serde(with = "serde_base64_vector")]
    pub secret: Vec<u8>,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(remote = "Merge", rename_all = "PascalCase")]
pub struct MergeAPI {
    pub lane: u64,
    pub nonce: u64,
}
