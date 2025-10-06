extern crate alloc;
use alloc::string::String;
use rustls::KeyLog;

/// A simple implementation of the [`KeyLog`] trait that logs TLS secrets using the log crate
#[derive(Debug)]
pub struct MyKeyLogger;

impl KeyLog for MyKeyLogger {
    /// Logs the TLS secrets.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        fn hex(bytes: &[u8]) -> String {
            let mut s = String::new();
            for b in bytes {
                s.push_str(&alloc::format!("{:02x}", b));
            }
            s
        }

        let msg = alloc::format!(
            "{label} {client_random} {secret}",
            label = label,
            client_random = hex(client_random),
            secret = hex(secret)
        );

        log::info!("KeyLog: {msg}");
    }
}
