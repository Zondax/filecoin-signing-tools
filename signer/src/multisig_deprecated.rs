use clock::ChainEpoch;
use forest_encoding::tuple::*;

/// Constructor parameters for multisig actor V1 (deprecated)
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParamsV1 {
    pub signers: Vec<fvm_shared::address::Address>,
    pub num_approvals_threshold: u64,
    pub unlock_duration: ChainEpoch,
}
