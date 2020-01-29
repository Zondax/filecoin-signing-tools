//! Fcservice Config
//!
//! See instructions in `commands.rs` to specify the path to your
//! application's configuration file and/or command-line options
//! for specifying it.

use serde::{Deserialize, Serialize};

/// Fcservice Configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FcserviceConfig {
    /// remote JSONRPC node configuration section
    pub remote_node: RemoteNodeSection,
    /// local JSONRPC node configuration section
    pub service: ServiceSection,
}

/// Default configuration settings.
///
/// Note: if your needs are as simple as below, you can
/// use `#[derive(Default)]` on FcserviceConfig instead.
impl Default for FcserviceConfig {
    fn default() -> Self {
        Self {
            remote_node: RemoteNodeSection::default(),
            service: ServiceSection::default(),
        }
    }
}

/// Remote Node configuration section.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteNodeSection {
    /// Remote node hostname (JSON RPC service)
    pub url: String,
    /// JSON web token
    pub jwt: String,
}

impl Default for RemoteNodeSection {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1".to_owned(),
            jwt: "".to_owned(),
        }
    }
}

/// Service configuration section.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSection {
    /// Service HTTP address host:port
    pub address: String,
}

impl Default for ServiceSection {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:303".to_owned(),
        }
    }
}
