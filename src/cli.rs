use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::logging::ColorMode;

#[derive(Debug, Parser)]
#[command(
    name = "tetherd",
    version,
    about = "Authenticated outbound tether daemon"
)]
pub struct Cli {
    /// Configuration file.
    #[arg(long, global = true, default_value = "tetherd.toml")]
    pub config: PathBuf,

    /// Override configured log level.
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Override configured log color mode.
    #[arg(long, global = true, value_enum)]
    pub log_color: Option<ColorMode>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run the public listener and local control socket.
    Daemon,
    /// Join a daemon from a private/internal host and maintain the outbound link.
    Join,
    /// Operate a running daemon through its local Unix socket.
    Ctl {
        #[command(subcommand)]
        action: CtlAction,
    },
    /// Generate a 256-bit PSK in base64 form.
    Keygen,
}

#[derive(Debug, Subcommand)]
pub enum CtlAction {
    /// List connected peers.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Execute a configured command profile on a connected peer.
    Exec {
        /// Peer credential configured on both sides.
        #[arg(long)]
        credential: String,
        /// Command profile ID from exec.commands on the join host.
        #[arg(long)]
        command: String,
        /// Requested timeout in seconds. The peer enforces its own maximum.
        #[arg(long)]
        timeout: Option<u64>,
        /// Emit structured JSON instead of command stdout/stderr.
        #[arg(long)]
        json: bool,
        /// Optional user arguments. The command profile must explicitly allow them.
        #[arg(last = true, num_args = 0.., trailing_var_arg = true)]
        args: Vec<String>,
    },
}
