#[cfg(test)]
pub mod tests {
    use crate::config::RemoteNodeSection;
    use std::env;

    pub fn get_remote_credentials() -> RemoteNodeSection {
        const DEFAULT_TEST_URL: &str = "http://127.0.0.1:1234/rpc/v0";
        const DEFAULT_JWT: &str = "";

        let url = match env::var_os("LOTUS_SECRET_URL") {
            Some(val) => String::from(val.to_string_lossy()),
            None => DEFAULT_TEST_URL.to_string(),
        };

        let jwt = match env::var_os("LOTUS_SECRET_JWT") {
            Some(val) => String::from(val.to_string_lossy()),
            None => DEFAULT_JWT.to_string(),
        };

        RemoteNodeSection { url, jwt }
    }
}
