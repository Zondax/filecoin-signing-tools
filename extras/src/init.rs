use cid::Cid;
use fil_actor_init::{ConstructorParams, ExecParams, ExecReturn};
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use serde::{Deserialize, Serialize};

use super::json::address;
use super::json::cid as json_cid;
use super::json::rawbytes;

#[derive(Serialize, Deserialize)]
#[serde(remote = "ConstructorParams", rename_all = "PascalCase")]
pub struct ConstructorParamsAPI {
    pub network_name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ExecParams", rename_all = "PascalCase")]
pub struct ExecParamsAPI {
    #[serde(with = "json_cid")]
    pub code_cid: Cid,
    #[serde(with = "rawbytes")]
    pub constructor_params: RawBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ExecReturn", rename_all = "PascalCase")]
pub struct ExecReturnAPI {
    #[serde(with = "address")]
    pub id_address: Address,
    #[serde(with = "address")]
    pub robust_address: Address,
}
