use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use fvm_shared::MethodNum;
use serde::{Deserialize, Serialize};

use super::json::address;
use super::json::rawbytes;
use super::json::tokenamount;

#[derive(Serialize, Deserialize)]
#[serde(remote = "Message", rename_all = "PascalCase")]
pub struct MessageAPI {
    #[serde(skip)]
    pub version: i64,
    #[serde(with = "address")]
    pub from: Address,
    #[serde(with = "address")]
    pub to: Address,
    #[serde(alias = "Nonce")]
    pub sequence: u64,
    #[serde(with = "tokenamount")]
    pub value: TokenAmount,
    #[serde(alias = "Method")]
    pub method_num: MethodNum,
    #[serde(with = "rawbytes")]
    pub params: RawBytes,
    pub gas_limit: i64,
    #[serde(with = "tokenamount")]
    pub gas_fee_cap: TokenAmount,
    #[serde(with = "tokenamount")]
    pub gas_premium: TokenAmount,
}
