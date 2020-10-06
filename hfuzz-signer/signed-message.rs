use core::convert::TryFrom;
use filecoin_signer::api::{
    MessageTx, MessageTxAPI, MessageTxNetwork, SignedMessageAPI, UnsignedMessageAPI,
};
use forest_address::Address;
use forest_crypto::{Signature, Signer};
use forest_message::{SignedMessage, UnsignedMessage};

struct DummySigner;

impl Signer for DummySigner {
    fn sign_bytes(&self, _: &[u8], _: &Address) -> Result<Signature, Box<dyn std::error::Error>> {
        Ok(Signature::new_secp256k1([0u8].to_vec()))
    }
}

fn main() {
    loop {
        honggfuzz::fuzz!(|data: (UnsignedMessageAPI, bool)| {
            let (unsigned_message_api, is_testnet) = data;

            let unsigned_message = if let Ok(r) = UnsignedMessage::try_from(&unsigned_message_api) {
                r
            } else {
                return;
            };

            let signed_message = if let Ok(r) = SignedMessage::new(unsigned_message, &DummySigner) {
                r
            } else {
                return;
            };

            let _ = MessageTxAPI::try_from(MessageTxNetwork {
                message_tx: MessageTx::SignedMessage(signed_message.clone()),
                testnet: is_testnet,
            });

            let _ = SignedMessageAPI::try_from(signed_message);
        });
    }
}
