use fvm_shared::crypto::signature::Signature;
use serde::{Deserialize, Serialize};
use fvm_shared::message::Message;

use super::message::MessageAPI;
use super::signature::SignatureAPI;

pub mod ref_fvm {
    // TODO: this is temporary. It should be part of ref-fvm
    use fvm_ipld_encoding::tuple::*;
    use fvm_ipld_encoding::Cbor;
    use fvm_shared::message::Message;
    use fvm_shared::crypto::signature::Signature;

    /// Represents a wrapped message with signature bytes.
    #[derive(Debug, Serialize_tuple, Deserialize_tuple)]
    pub struct SignedMessage {
        pub message: Message,
        pub signature: Signature,
    }

    impl Cbor for SignedMessage {}
}

#[derive(Debug, Serialize, Deserialize)]
#[serde( remote = "ref_fvm::SignedMessage", rename_all = "PascalCase")]
pub struct SignedMessageAPI {
    #[serde(with = "MessageAPI")]
    pub message: Message,
    #[serde(with = "SignatureAPI")]
    pub signature: Signature,
}