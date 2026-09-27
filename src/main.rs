use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use tetherd::cli::{Cli, Commands, CtlAction};
use tetherd::config::Config;
use tetherd::logging::{parse_level, resolve_color, Logger};
use tetherd::protocol::message::ControlRequest;
use tetherd::{ctl, daemon, join, keygen, Error, Result};

fn resolve_logging(
    cli: &Cli,
    config: Option<&Config>,
) -> Result<(log::LevelFilter, tetherd::logging::ColorMode)> {
    let level = if let Some(level) = &cli.log_level {
        parse_level(level)?
    } else if let Ok(level) = std::env::var("RUST_LOG") {
        parse_level(&level)?
    } else if let Some(config) = config {
        config.log_level()?
    } else {
        log::LevelFilter::Info
    };
    let color = resolve_color(cli.log_color, config.map(|c| c.log.color));
    Ok((level, color))
}

#[tokio::main]
async fn main() -> ExitCode {
    match real_main().await {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("tetherd: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn real_main() -> Result<i32> {
    let cli = Cli::parse();

    if matches!(&cli.command, Commands::Keygen) {
        let (level, color) = resolve_logging(&cli, None)?;
        Logger::init(level, color)?;
        println!("{}", keygen::generate());
        return Ok(0);
    }

    let config = Arc::new(Config::load(&cli.config)?);
    let (level, color) = resolve_logging(&cli, Some(&config))?;
    Logger::init(level, color)?;
    log::info!("tetherd v{} starting", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Commands::Daemon => {
            let (_shutdown_tx, shutdown_rx) = shutdown_channel();
            daemon::run(config, shutdown_rx).await?;
            Ok(0)
        }
        Commands::Join => {
            let (_shutdown_tx, shutdown_rx) = shutdown_channel();
            join::run(config, shutdown_rx).await?;
            Ok(0)
        }
        Commands::Ctl { action } => {
            let (request, json, request_timeout) = match action {
                CtlAction::List { json } => (
                    ControlRequest::List,
                    json,
                    Duration::from_secs(
                        config.daemon.control_request_timeout_secs.saturating_add(2),
                    ),
                ),
                CtlAction::Exec {
                    credential,
                    command,
                    timeout,
                    json,
                    args,
                } => {
                    let remote_timeout = timeout
                        .unwrap_or(config.daemon.control_timeout_secs)
                        .clamp(1, config.daemon.control_timeout_secs);
                    (
                        ControlRequest::Exec {
                            credential,
                            command,
                            args,
                            timeout_secs: timeout,
                        },
                        json,
                        Duration::from_secs(remote_timeout.saturating_add(10)),
                    )
                }
            };
            let response =
                ctl::request(&config.daemon.control_socket, request, request_timeout).await?;
            ctl::print_response(response, json)
        }
        Commands::Keygen => Err(Error::Protocol("unreachable keygen dispatch".into())),
    }
}

fn shutdown_channel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    let (tx, rx) = watch::channel(false);
    let signal_tx = tx.clone();
    tokio::spawn(async move {
        match wait_for_shutdown_signal().await {
            Ok(()) => {
                let _ = signal_tx.send(true);
            }
            Err(err) => log::error!("failed to install shutdown signal handler error={err}"),
        }
    });
    (tx, rx)
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}
