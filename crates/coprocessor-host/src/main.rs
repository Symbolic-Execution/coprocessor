//! Coprocessor Host binary entry point.
//!
//! The scaffold binary loads local-development configuration, starts the
//! host, prints its readiness, and shuts down cleanly. Future slices will
//! replace the hard-coded local config with the loader chosen in issue #18
//! and will keep the process alive while chain ingestion, the scheduler, and
//! the Internal Coordinator API run.

use std::process::ExitCode;

use coprocessor_host::{CoprocessorHost, HostConfig, HostStartError, Readiness};

fn main() -> ExitCode {
    let config = HostConfig::for_local_development();
    let mut host = CoprocessorHost::new(config);

    if let Err(err) = host.start() {
        eprintln!("coprocessor-host: failed to start: {err:?}");
        return match err {
            HostStartError::InvalidConfig(_) => ExitCode::from(2),
            HostStartError::AlreadyShutDown => ExitCode::from(3),
        };
    }

    match host.readiness() {
        Readiness::Ready => println!("coprocessor-host: ready"),
        Readiness::ConfigurationLoaded { unavailable } => println!(
            "coprocessor-host: configuration loaded; dependencies pending: {unavailable:?}"
        ),
        Readiness::NotStarted | Readiness::ShutDown => {
            eprintln!("coprocessor-host: unexpected readiness state after start");
            return ExitCode::from(4);
        }
    }

    host.shutdown();
    ExitCode::SUCCESS
}
