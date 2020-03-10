//! Main entry point for Fcservice

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use filecoin_service::application::APPLICATION;

/// Boot Fcservice
fn main() {
    abscissa_core::boot(&APPLICATION);
}
