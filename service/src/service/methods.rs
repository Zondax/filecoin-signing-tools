//////! Filecoin Service RPC Client

use crate::config::RemoteNodeSection;
use crate::service::client;
use crate::service::error::ServiceError;
use filecoin_signer::api::{
    CreateMultisigMessageAPI, ProposalMessageParamsAPI, SignedMessageAPI, UnsignedMessageAPI,
};
use filecoin_signer::signature::Signature;
use filecoin_signer::{CborBuffer, PrivateKey};
use jsonrpc_core::{MethodCall, Success, Version};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::convert::TryFrom;

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateMultisigParamsAPI {
    pub tx_params: CreateMultisigMessageAPI,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProposeMultisigTxParamsAPI {
    pub transaction: UnsignedMessageAPI,
    pub proposal_params: ProposalMessageParamsAPI,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApproveCancelMultisigTxParamsAPI {
    pub transaction: UnsignedMessageAPI,
    pub proposal_params: ProposalMessageParamsAPI,
    pub txn_id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SendSignedTxParamsAPI {
    pub signed_tx: SignedMessageAPI,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignTransactionParamsAPI {
    pub transaction: UnsignedMessageAPI,
    pub prvkey_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetNonceParamsAPI {
    pub account: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyDeriveParamsAPI {
    pub mnemonic: String,
    pub path: String,
    #[serde(default)]
    pub password: String,
    pub language_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyDeriveFromSeedParamsAPI {
    pub seed: String,
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyDeriveResultAPI {
    pub private_base64: String,
    pub public_hexstring: String,
    pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransctionParseParamsAPI {
    pub cbor_hex: String,
    pub testnet: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifySignatureParamsAPI {
    pub signature_hex: String,
    pub message_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetStatusParamsAPI {
    pub cid_message: String,
}

pub async fn key_generate_mnemonic(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let mnemonic = filecoin_signer::key_generate_mnemonic()?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(mnemonic.0),
        id: c.id,
    };

    Ok(so)
}

pub async fn key_derive(c: MethodCall, _: RemoteNodeSection) -> Result<Success, ServiceError> {
    let params = c.params.parse::<KeyDeriveParamsAPI>()?;

    let key_address = filecoin_signer::key_derive(
        &params.mnemonic,
        &params.path,
        &params.password,
        &params.language_code,
    )?;

    let result = KeyDeriveResultAPI {
        public_hexstring: hex::encode(&key_address.public_key.to_vec()),
        private_base64: base64::encode(&key_address.private_key.0),
        address: key_address.address,
    };

    let result_json = serde_json::to_value(&result)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: result_json,
        id: c.id,
    };

    Ok(so)
}

pub async fn key_derive_from_seed(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params = c.params.parse::<KeyDeriveFromSeedParamsAPI>()?;

    let seed = hex::decode(&params.seed)?;

    let key_address = filecoin_signer::key_derive_from_seed(&seed, &params.path)?;

    let result = KeyDeriveResultAPI {
        public_hexstring: hex::encode(&key_address.public_key.to_vec()),
        private_base64: base64::encode(&key_address.private_key.0),
        address: key_address.address,
    };

    let result_json = serde_json::to_value(&result)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: result_json,
        id: c.id,
    };

    Ok(so)
}

pub async fn transaction_serialize(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params = c.params.parse::<UnsignedMessageAPI>()?;
    let cbor_hexstring = filecoin_signer::transaction_serialize(&params)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(cbor_hexstring.0),
        id: c.id,
    };

    Ok(so)
}

pub async fn transaction_parse(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params = c.params.parse::<TransctionParseParamsAPI>()?;
    let cbor_data = CborBuffer(hex::decode(&params.cbor_hex)?);

    let message_parsed = filecoin_signer::transaction_parse(&cbor_data, params.testnet)?;

    let tx = serde_json::to_string(&message_parsed)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(tx),
        id: c.id,
    };

    Ok(so)
}

pub async fn sign_transaction(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params = c.params.parse::<SignTransactionParamsAPI>()?;

    let private_key = PrivateKey::try_from(params.prvkey_base64)?;

    let signed_message = filecoin_signer::transaction_sign(&params.transaction, &private_key)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: serde_json::to_value(&signed_message)?,
        id: c.id,
    };

    Ok(so)
}

pub async fn verify_signature(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params = c.params.parse::<VerifySignatureParamsAPI>()?;

    let signature = Signature::try_from(params.signature_hex)?;
    let message = CborBuffer(hex::decode(&params.message_hex)?);

    let result = filecoin_signer::verify_signature(&signature, &message)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(result),
        id: c.id,
    };

    Ok(so)
}

pub async fn get_status(c: MethodCall, config: RemoteNodeSection) -> Result<Success, ServiceError> {
    let call_params = c.params.parse::<GetStatusParamsAPI>()?;
    let params = json!({"/": call_params.cid_message.to_string()});
    let result = client::get_status(&config.url, &config.jwt, params).await?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result,
        id: c.id,
    };

    Ok(so)
}

pub async fn get_nonce(c: MethodCall, config: RemoteNodeSection) -> Result<Success, ServiceError> {
    let params = c.params.parse::<GetNonceParamsAPI>()?;

    let result = client::get_nonce(&config.url, &config.jwt, &params.account).await?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(result),
        id: c.id,
    };

    Ok(so)
}

pub async fn send_signed_tx(
    c: MethodCall,
    config: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    // Deserialize and back again to be sure is all valid
    let call_params = c.params.parse::<SendSignedTxParamsAPI>()?;
    let signed_tx_json = serde_json::to_string(&call_params.signed_tx)?;
    let signed_tx = serde_json::from_str(&signed_tx_json)?;

    // send to remote node
    let result = client::send_signed_tx(&config.url, &config.jwt, signed_tx).await?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result,
        id: c.id,
    };

    Ok(so)
}

pub async fn send_sign(c: MethodCall, config: RemoteNodeSection) -> Result<Success, ServiceError> {
    let params = c.params.parse::<SignTransactionParamsAPI>()?;

    let private_key = PrivateKey::try_from(params.prvkey_base64)?;

    // signed message
    let signed_message = filecoin_signer::transaction_sign(&params.transaction, &private_key)?;

    let result = client::is_mainnet(&config.url, &config.jwt).await?;

    if result {
        // Is mainnet
        if signed_message.message.from.starts_with('t') {
            return Err(ServiceError::WrongNetwork);
        }
    } else {
        // Not mainnet
        if signed_message.message.from.starts_with('f') {
            return Err(ServiceError::WrongNetwork);
        }
    }

    let signed_message_value = serde_json::to_value(&signed_message)?;

    // send to remote node
    let result = client::send_signed_tx(&config.url, &config.jwt, signed_message_value).await?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result,
        id: c.id,
    };

    Ok(so)
}

pub async fn create_multisig(c: MethodCall, _: RemoteNodeSection) -> Result<Success, ServiceError> {
    let params: CreateMultisigParamsAPI = c.params.parse::<CreateMultisigParamsAPI>()?;

    let tx_params: CreateMultisigMessageAPI = params.tx_params;

    let result: UnsignedMessageAPI = filecoin_signer::create_multisig(
        tx_params.from,
        tx_params.signers,
        tx_params.value,
        tx_params.threshold,
        tx_params.nonce,
        tx_params.unlock_duration,
        tx_params.start_epoch,
        tx_params.gas_limit,
        tx_params.gas_fee_cap,
        tx_params.gas_premium,
    )?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: serde_json::to_value(result)?,
        id: c.id,
    };

    Ok(so)
}

pub async fn propose_multisig_tx(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params: ProposeMultisigTxParamsAPI = c.params.parse::<ProposeMultisigTxParamsAPI>()?;

    let tx: UnsignedMessageAPI = params.transaction;
    let proposal_params: ProposalMessageParamsAPI = params.proposal_params;

    let result: UnsignedMessageAPI = filecoin_signer::proposal_multisig_message(
        tx.to,
        proposal_params.to,
        tx.from,
        proposal_params.value,
        tx.nonce,
        tx.gas_limit,
        tx.gas_fee_cap,
        tx.gas_premium,
        proposal_params.method,
        proposal_params.params,
    )?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: serde_json::to_value(result)?,
        id: c.id,
    };

    Ok(so)
}

pub async fn approve_multisig_tx(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params: ApproveCancelMultisigTxParamsAPI =
        c.params.parse::<ApproveCancelMultisigTxParamsAPI>()?;

    let tx: UnsignedMessageAPI = params.transaction;
    let proposal_params: ProposalMessageParamsAPI = params.proposal_params;

    let result: UnsignedMessageAPI = filecoin_signer::approve_multisig_message(
        tx.to,
        params.txn_id,
        proposal_params.requester,
        proposal_params.to,
        proposal_params.value,
        tx.from,
        tx.nonce,
        tx.gas_limit,
        tx.gas_fee_cap,
        tx.gas_premium,
    )?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: serde_json::to_value(result)?,
        id: c.id,
    };

    Ok(so)
}

pub async fn cancel_multisig_tx(
    c: MethodCall,
    _: RemoteNodeSection,
) -> Result<Success, ServiceError> {
    let params: ApproveCancelMultisigTxParamsAPI =
        c.params.parse::<ApproveCancelMultisigTxParamsAPI>()?;

    let tx: UnsignedMessageAPI = params.transaction;
    let proposal_params: ProposalMessageParamsAPI = params.proposal_params;

    let result: UnsignedMessageAPI = filecoin_signer::cancel_multisig_message(
        tx.to,
        params.txn_id,
        proposal_params.requester,
        proposal_params.to,
        proposal_params.value,
        tx.from,
        tx.nonce,
        tx.gas_limit,
        tx.gas_fee_cap,
        tx.gas_premium,
    )?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: serde_json::to_value(result)?,
        id: c.id,
    };

    Ok(so)
}

#[cfg(test)]
mod tests {
    use crate::service::methods::get_status;
    use crate::service::test_helper::tests::get_remote_credentials;
    use jsonrpc_core::{Id, MethodCall, Params, Version};
    use serde_json::json;

    #[tokio::test]
    async fn example_get_status_transaction_fail() {
        let params_str = json!({ "cid_message": "bafy2bzacedbo3svni7n2jb57exuqh4v5zvjjethf3p74zgv7yfdtczce2yu4u" });
        let params: Params =
            serde_json::from_str(&params_str.to_string()).expect("could not deserialize");

        /*let expected_response = json!({
            "jsonrpc":"2.0",
            "result":null,
            "id":1,
            "error":{
                "code":1,
                "message":
                "blockstore: block not found"
            }
        });*/

        let mc = MethodCall {
            jsonrpc: Some(Version::V2),
            method: "get_status".to_string(),
            params,
            id: Id::Num(0),
        };

        let config = get_remote_credentials();
        let status = get_status(mc, config).await;

        println!("{:?}", status);

        assert!(status.is_err());
    }

    #[tokio::test]
    async fn example_get_status_transaction_fail_2() {
        let params_str = json!({ "cid_message": "bafy2bzaceaxm23epjsmh75yvzcecsrbavlmkcxnva66bkdebdcnyw3bjrc74u" });
        let params: Params =
            serde_json::from_str(&params_str.to_string()).expect("could not deserialize");

        /*let expected_response = json!({
            "jsonrpc":"2.0",
            "result":null,
            "id":1,
            "error":{
                "code":1,
                "message":"cbor input had wrong number of fields"
            }
        });*/

        let mc = MethodCall {
            jsonrpc: Some(Version::V2),
            method: "get_status".to_string(),
            params,
            id: Id::Num(0),
        };

        let config = get_remote_credentials();
        let status = get_status(mc, config).await;

        println!("{:?}", status);

        assert!(status.is_err());
    }
}
