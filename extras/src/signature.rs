use fvm_shared::crypto::signature::{Signature, SignatureType};
use serde::{de, Deserialize, Deserializer, Serializer, Serialize};
use fvm_ipld_encoding::serde_bytes;

/*use super::json::serde_base64_vector;

#[derive(Serialize, Deserialize)]
#[serde(remote = "Signature", rename_all = "PascalCase")]
pub struct SignatureAPI {
    pub sig_type: SignatureType,
    #[serde(with = "serde_base64_vector")]
    pub bytes: Vec<u8>,
}*/

#[derive(Serialize, Deserialize)]
struct JsonSignature {
    sig_type: SignatureType,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}
pub fn serialize<S: Serializer>(v: &Signature, s: S) -> Result<S::Ok, S::Error> {
    JsonSignature {
        bytes: v.bytes().to_vec(),
        sig_type: v.signature_type(),
    }.serialize(s)
}
pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
where
    D: Deserializer<'de>,
{
    // Not working
}