use std::sync::atomic::{AtomicU8, Ordering};

use shhnote_core::config::LogLevel;

// Error unless `SHH_LOG_LEVEL` says otherwise. Everything goes to stderr; requests, addresses
// and identifiers are never logged at any level (SPEC principle 4).
static LEVEL: AtomicU8 = AtomicU8::new(0);

fn rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
        LogLevel::Debug => 3,
        LogLevel::Trace => 4,
    }
}

pub fn init(level: LogLevel) {
    LEVEL.store(rank(level), Ordering::Relaxed);
}

pub fn enabled(level: LogLevel) -> bool {
    rank(level) <= LEVEL.load(Ordering::Relaxed)
}

pub fn name(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warning",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    }
}

#[macro_export]
macro_rules! log_at {
    ($level:expr, $($arg:tt)*) => {
        if $crate::log::enabled($level) {
            eprintln!("{}: {}", $crate::log::name($level), format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log_at!(::shhnote_core::config::LogLevel::Error, $($arg)*) };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log_at!(::shhnote_core::config::LogLevel::Warn, $($arg)*) };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log_at!(::shhnote_core::config::LogLevel::Info, $($arg)*) };
}
