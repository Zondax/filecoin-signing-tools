pub mod multisig;
pub mod paych;

use forest_address::Address;
use forest_cid::Cid;
use forest_encoding::tuple::*;
use forest_vm::Serialized;
use lazy_static::lazy_static;

/// Methods init
/// https://github.com/filecoin-project/specs-actors/blob/master/actors/builtin/methods.go#L21
#[repr(u64)]
pub enum MethodInit {
    Constructor = 1,
    Exec = 2,
}

/// Exec Params
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ExecParams {
    pub code_cid: Cid,
    pub constructor_params: Serialized,
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
