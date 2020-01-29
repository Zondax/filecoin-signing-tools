//! `start` subcommand - example of how to write a subcommand

/// App-local prelude includes `app_reader()`/`app_writer()`/`app_config()`
/// accessors along with logging macros. Customize as you see fit.
use crate::prelude::*;

use crate::config::FcserviceConfig;
use abscissa_core::{config, Command, FrameworkError, Options, Runnable};
use crate::rpc_server;
use crate::rpc_client;
use std::net::SocketAddr;

/// `start` subcommand
///
/// The `Options` proc macro generates an option parser based on the struct
/// definition, and is defined in the `gumdrop` crate. See their documentation
/// for a more comprehensive example:
///
/// <https://docs.rs/gumdrop/>
#[derive(Command, Debug, Options)]
pub struct StartCmd {
    /// To whom are we saying hello?
    #[options(free)]
    recipient: Vec<String>,
}

impl Runnable for StartCmd {
    /// Start the application.
    fn run(&self) {
        let config = app_config();
        println!("Remote URL    : {}", &config.remote_node.url);
        println!("Local address : {}", &config.service.address);

        rpc_client::start(&config.remote_node.url);
        let server_addr: SocketAddr = "127.0.0.1:3030".parse().unwrap();
        rpc_server::start(&server_addr);
    }
}

impl config::Override<FcserviceConfig> for StartCmd {
    // Process the given command line options, overriding settings from
    // a configuration file using explicit flags taken from command-line
    // arguments.
    fn override_config(
        &self,
        mut config: FcserviceConfig,
    ) -> Result<FcserviceConfig, FrameworkError> {
//        if !self.recipient.is_empty() {
//            config.remote_node.url = self.recipient.join(" ");
//        }

        Ok(config)
    }
}
