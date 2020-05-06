/*******************************************************************************
*   (c) 2020 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

use ledger_transport::errors::TransportError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Filecoin App Error
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq, Deserialize, Serialize)]
pub enum LedgerError {
    /// Invalid version error
    #[error("This version is not supported")]
    InvalidVersion,
    /// The message cannot be empty
    #[error("message cannot be empty")]
    InvalidEmptyMessage,
    /// The size fo the message to sign is invalid
    #[error("message size is invalid (too big)")]
    InvalidMessageSize,
    /// Public Key is invalid
    #[error("received an invalid PK")]
    InvalidPK,
    /// No signature has been returned
    #[error("received no signature back")]
    NoSignature,
    /// The signature is not valid
    #[error("received an invalid signature")]
    InvalidSignature,
    /// The derivation is invalid
    #[error("invalid derivation path")]
    InvalidDerivationPath,
    /// The derivation is invalid
    #[error("Transport | {0}")]
    TransportError(#[from] TransportError),
    /// Secp256k1 related errors
    #[error("Secp256k1")]
    Secp256k1,
    /// Utf8 related errors
    #[error("Utf8 conversion error")]
    Utf8,
    // FIXME: We need to expose Ledger specific erros, including error code
}
