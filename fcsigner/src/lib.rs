pub fn key_generate() {
    // TODO: return keypair (pub/priv + address)
}

pub fn key_derive() {
    // TODO mnemonic + path
    // TODO: return keypair (pub/priv + address)
}

pub fn transaction_create() {
    // TODO: tx params as JSON
    // TODO: return unsigned transaction serialized as CBOR
}

pub fn transaction_parse() {
    // TODO: serialized tx
    // TODO: tx as JSON
}

pub fn sign_transaction() {
    // TODO: tx params, private key
    // TODO: return signed transaction as CBOR
}

pub fn sign_message() {
    // TODO: message ?
    // TODO: return signature
}

pub fn verify_signature() -> Result<bool, ()> {
    // TODO: receive pubkey, signature, message
    // TODO: true is valid
    Ok(false)
}

#[cfg(test)]
mod tests {
    use crate::{verify_signature};

    #[test]
    fn verify_random_signature_fails() {
        assert_eq!( verify_signature().expect("error while verifying"), false )
    }
}
