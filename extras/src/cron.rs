use serde::{Serialize, Deserialize};
use fil_actor_cron::{ConstructorParams, Entry};
use fvm_shared::MethodNum;
use fvm_shared::address::Address;

#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "ConstructorParams")]
pub struct ConstructorParamsAPI {
    /// Entries is a set of actors (and corresponding methods) to call during EpochTick.
    pub entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "Entry")]
pub struct EntryAPI {
    /// The actor to call (ID address)
    pub receiver: Address,
    /// The method number to call (must accept empty parameters)
    pub method_num: MethodNum,
}