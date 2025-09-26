// ########################################################
// # Example functions to test the TLS and HTTPS modules  #
// ########################################################

extern crate alloc;

use crate::vsock::stream::VsockStream;

use super::constants::IN_BUF_SIZE;

const REMOTE_PORT: u32 = 12345;
const REMOTE_CID: u64 = 2;
const SERVER_DNS: &str = "localhost";

use super::connection::TlsClient;

/// Test function to interact with an HTTPS server as a client
/// using direct TLS connection
pub fn test_tls() {
    log::info!("Opening TLS...");
    let mut tls_connection = TlsClient::new(false)
        .connect(
            VsockStream::connect(REMOTE_PORT, REMOTE_CID)
                .expect("Failed to connect to VsockStream"),
            SERVER_DNS,
        )
        .expect("Failed to create TLS connection");
    tls_connection
        .complete_handshake()
        .expect("Failed to complete TLS handshake");
    let http_request =
        "GET /hello.html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".as_bytes();
    // ########################################################
    // Sending HTTP request
    // ########################################################
    tls_connection
        .write_tls(http_request)
        .expect("Failed to write application data over TLS");
    // ########################################################
    // Receiving HTTP response
    // ########################################################
    // This assume that the response is on a single read, otherwise
    // it will give an error when trying to close the connection
    let mut data_from_server = alloc::vec![0u8; IN_BUF_SIZE]; // this is arbitrary
    tls_connection
        .read_tls(&mut data_from_server)
        .expect("Failed to read application data over TLS");
    let response = core::str::from_utf8(&data_from_server).unwrap_or("<Invalid UTF-8>");
    log::info!("Response:\n {}", response);
    // ########################################################
    // Closing TLS connection
    // ########################################################
    tls_connection
        .close_tls()
        .expect("Failed to close TLS connection");
    log::info!("TLS conversation completed.");
}
