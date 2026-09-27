use std::time::Duration;

pub mod connection;
pub mod control;
pub mod listener;

pub use listener::run;

pub fn output_transfer_budget(output_idle_timeout: Duration) -> Duration {
    output_idle_timeout
        .saturating_mul(4)
        .max(Duration::from_secs(30))
        .min(Duration::from_secs(300))
}
