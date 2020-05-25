use filecoin_signer_ledger::errors::LedgerError;
use filecoin_signer_ledger::TransportError;
use serde::{Deserialize, Serialize};

/// FilecoinApp Error message
#[derive(Deserialize, Serialize)]
pub struct Error {
    /// Message return code
    pub return_code: u16,
    /// Error message
    pub error_message: String,
}

pub fn ledger_error_to_javascript_error(err: LedgerError) -> Error {
    match err {
        LedgerError::TransportError(err) => {
            transport_error_to_javascript_error(err)
        },
        _ => {
            Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            }
        }
    }
}

fn transport_error_to_javascript_error(err: TransportError) -> Error {
    match err {
        TransportError::APDU(retcode, error_message) => {
            Error {
                return_code: retcode,
                error_message: error_message.to_string(),
            }
        },
        _ => {
            Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            }
        }
    }
}
