//! `start` subcommand - example of how to write a subcommand

/// App-local prelude includes `app_reader()`/`app_writer()`/`app_config()`
/// accessors along with logging macros.
use crate::config::FcserviceConfig;
use crate::service;
use abscissa_core::{config, Command, FrameworkError, Options, Runnable};

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
    remote_url: String,
}

impl Runnable for StartCmd {
    /// Start the application.
    fn run(&self) {
        service::service_main();
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
        if !self.remote_url.is_empty() {
            config.remote_node.url = self.remote_url.to_string();
        }

        Ok(config)
    }
}
