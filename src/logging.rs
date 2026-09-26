use chrono::Local;
use log::{Level, LevelFilter, Log, Metadata, Record};
use serde::{Deserialize, Serialize};
use std::io::{IsTerminal, Write};
use std::str::FromStr;
use std::sync::Mutex;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

pub struct Logger {
    level: LevelFilter,
    use_color: bool,
    inner: Mutex<()>,
}

impl Logger {
    pub fn init(level: LevelFilter, color_mode: ColorMode) -> Result<()> {
        let mut use_color = match color_mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => std::io::stderr().is_terminal(),
        };

        if std::env::var_os("NO_COLOR").is_some() {
            use_color = false;
        } else if std::env::var_os("FORCE_COLOR").is_some() {
            use_color = true;
        }

        let logger = Box::new(Self {
            level,
            use_color,
            inner: Mutex::new(()),
        });
        log::set_boxed_logger(logger)
            .map_err(|e| Error::Config(format!("logger initialization failed: {e}")))?;
        log::set_max_level(level);
        Ok(())
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let Ok(_guard) = self.inner.lock() else {
            return;
        };
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
        let level = record.level();
        let mut out = std::io::stderr().lock();
        if self.use_color {
            let _ = writeln!(
                out,
                "{} [\x1b[{}m{}\x1b[0m] {}",
                ts,
                level_color_code(level),
                level,
                record.args()
            );
        } else {
            let _ = writeln!(out, "{} [{}] {}", ts, level, record.args());
        }
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

fn level_color_code(level: Level) -> u8 {
    match level {
        Level::Error => 31,
        Level::Warn => 33,
        Level::Info => 32,
        Level::Debug => 34,
        Level::Trace => 90,
    }
}

pub fn parse_level(value: &str) -> Result<LevelFilter> {
    LevelFilter::from_str(value).map_err(|_| Error::Config(format!("invalid log level: {value}")))
}
