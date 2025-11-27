// Private modules for TLS implementation
mod buffer;
mod constants;
mod crypto_provider;
mod key_logger;
mod time_provider;

// Public modules for TLS implementation
pub mod connection;
pub mod error;
pub mod examples;
pub mod random;
pub use constants::MAX_TLS_RECORD_LEN;
