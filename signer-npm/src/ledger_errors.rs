use filecoin_signer_ledger::LedgerAppError;
use serde::{Deserialize, Serialize};

/// FilecoinApp Error message
#[derive(Deserialize, Serialize)]
pub struct Error {
    /// Message return code
    pub return_code: u16,
    /// Error message
    pub error_message: String,
}

pub fn ledger_error_to_javascript_error(err: LedgerAppError) -> Error {
    match err {
        LedgerAppError::AppSpecific(err, message) => Error {
            return_code: err,
            error_message: message,
        },
        _ => Error {
            return_code: 0x6f00,
            error_message: err.to_string(),
        },
    }
}
