use fil_actor_cron::{ConstructorParams, Entry};
use fvm_shared::address::Address;
use fvm_shared::MethodNum;
use serde::{Deserialize, Serialize};

use super::json::address;

#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "ConstructorParams", rename_all = "PascalCase")]
pub struct ConstructorParamsAPI {
    pub entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "Entry", rename_all = "PascalCase")]
pub struct EntryAPI {
    #[serde(with = "address")]
    pub receiver: Address,
    pub method_num: MethodNum,
}
