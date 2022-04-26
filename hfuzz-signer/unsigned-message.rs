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

            let _ = MessageTxAPI::try_from(MessageTxNetwork {
                message_tx: MessageTx::UnsignedMessage(unsigned_message.clone()),
                testnet: is_testnet,
            });

            let another_uma = if let Ok(r) = UnsignedMessageAPI::try_from(unsigned_message) {
                r
            } else {
                return;
            };

            assert_eq!(unsigned_message_api, another_uma)
        });
    }*/
}
