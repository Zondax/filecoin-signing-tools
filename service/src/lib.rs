//! Fcservice
//!
//! Application based on the [Abscissa] framework.
//!
//! [Abscissa]: https://github.com/iqlusioninc/abscissa

// Tip: Deny warnings with `RUSTFLAGS="-D warnings"` environment variable in CI

#![cfg_attr(
    not(test),
    deny(
        clippy::option_unwrap_used,
        clippy::option_expect_used,
        clippy::result_unwrap_used,
        clippy::result_expect_used,
    )
)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_lifetimes,
    unused_qualifications
)]

pub mod application;
pub mod commands;
pub mod config;
pub mod error;
pub mod prelude;
mod service;
