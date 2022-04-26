fn main() {
    /* FIXME
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
    }*/
}
