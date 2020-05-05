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

// #![deny(warnings, trivial_casts, trivial_numeric_casts)]
// #![deny(unused_import_braces, unused_qualifications)]
// #![deny(missing_docs)]
// #![doc(html_root_url = "https://docs.rs/ledger-filecoin/0.1.0")]

use crate::errors::Error;
use crate::TransportWrapperTrait;
use ledger_generic::{ApduAnswer, ApduCommand};

use js_sys;
use wasm_bindgen_futures::JsFuture;

/// Transport struct for non-wasm arch
pub struct ApduTransport {
    /// Contain javascript transport object
    pub transport_wrapper: Box<dyn TransportWrapperTrait>,
}

/// Transport Impl for wasm
impl ApduTransport {
    /// Use to talk to the ledger device
    pub async fn exchange(&self, apdu_command: ApduCommand) -> Result<ApduAnswer, Error> {
        let promise = self
            .transport_wrapper
            .exchange_apdu(&apdu_command.serialize());

        let future = JsFuture::from(promise);
        let answer = future.await.map_err(|_e| Error::TransportError)?;
        let data = js_sys::Uint8Array::new(&answer).to_vec();

        // FIXME: if the reply is < 2 bytes, this is a serious error

        // FIXME: This is incorrect. The retcode are the last two bytes in data
        Ok(ApduAnswer {
            data: data,
            retcode: 0x9000,
        })
    }
}
