use clock::ChainEpoch;
use forest_address::Address;
use forest_encoding::tuple::*;

/// Constructor parameters for multisig actor V1 (deprecated)
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParamsV1 {
    pub signers: Vec<Address>,
    pub num_approvals_threshold: usize,
    pub unlock_duration: ChainEpoch,
}