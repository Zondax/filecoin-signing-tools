use cid::Cid;
use fvm_shared::address::Address;
use fvm_shared::encoding::RawBytes;
use fil_actor_init::{ConstructorParams, ExecParams, ExecReturn};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(remote = "ConstructorParams")]
pub struct ConstructorParamsAPI {
    pub network_name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ExecParams")]
pub struct ExecParamsAPI {
    pub code_cid: Cid,
    pub constructor_params: RawBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ExecReturn")]
pub struct ExecReturnAPI {
    /// ID based address for created actor
    pub id_address: Address,
    /// Reorg safe address for actor
    pub robust_address: Address,
}
