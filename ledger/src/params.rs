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
#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/ledger-filecoin/0.1.0")]

pub const CLA: u8 = 0x06;
pub const INS_GET_VERSION: u8 = 0x00;
pub const INS_GET_ADDR_SECP256K1: u8 = 0x01;
pub const INS_SIGN_SECP256K1: u8 = 0x02;
pub const USER_MESSAGE_CHUNK_SIZE: usize = 250;

pub enum PayloadType {
    Init = 0x00,
    Add = 0x01,
    Last = 0x02,
}

pub enum APDUErrors {
    NoError = 0x9000,
}
