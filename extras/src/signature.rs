use fvm_shared::crypto::signature::{Signature, SignatureType};
use serde::{Deserialize, Serialize};

use super::json::serde_base64_vector;

#[derive(Serialize, Deserialize)]
#[serde(remote = "Signature", rename_all = "PascalCase")]
pub struct SignatureAPI {
    pub sig_type: SignatureType,
    #[serde(with = "serde_base64_vector")]
    pub bytes: Vec<u8>,
}