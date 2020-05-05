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
//! Support library for Filecoin Ledger Nano S/X apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/ledger-filecoin/0.1.0")]

use crate::errors::Error;
use crate::errors::Error::TransportError;
use futures::future;
use ledger_generic::{ApduAnswer, ApduCommand};

/// Transport struct for non-wasm arch
pub struct ApduTransport {
    /// Native rust transport
    pub transport_wrapper: ledger::LedgerApp,
}

impl ApduTransport {
    /// Use to talk to the ledger device
    pub async fn exchange(&self, command: ApduCommand) -> Result<ApduAnswer, Error> {
        let call = self
            .transport_wrapper
            .exchange(command)
            .map_err(|_| TransportError)?;

        future::ready(Ok(call)).await
    }
}
