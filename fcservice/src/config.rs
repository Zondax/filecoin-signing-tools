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
    /// An example configuration section
    pub remote_node: RemoteNodeSection,
}

/// Default configuration settings.
///
/// Note: if your needs are as simple as below, you can
/// use `#[derive(Default)]` on FcserviceConfig instead.
impl Default for FcserviceConfig {
    fn default() -> Self {
        Self {
            remote_node: RemoteNodeSection::default(),
        }
    }
}

/// Remote Node configuration section.
///
/// Delete this and replace it with your actual configuration structs.
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
