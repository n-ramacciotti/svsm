// ########################################################
// # Example functions to test the TLS connection
// ########################################################

extern crate alloc;

use crate::error::SvsmError;
use crate::vsock::virtio_vsock::VsockStream;

use super::constant::IN_BUF_SIZE;

const LOCAL_PORT: u32 = 1234;
const REMOTE_PORT: u32 = 12345;
const REMOTE_CID: u64 = 2;
const SERVER_DNS: &str = "localhost";

use super::connection::{TlsClient, TlsConnection};

/// Test function to perform a simple HTTPS GET request over TLS
pub fn test_https() {
    log::info!("Opening TLS...");

    let mut tls_connection = TlsClient::new(false)
        .connect(
            VsockStream::connect(LOCAL_PORT, REMOTE_PORT, REMOTE_CID)
                .expect("Failed to connect to VsockStream"),
            SERVER_DNS,
        )
        .expect("Failed to create TLS connection");

    tls_connection
        .complete_handshake()
        .expect("Failed to complete TLS handshake");

    let http_request =
        "GET /hello.html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".as_bytes();

    log::info!("########################################################");
    log::info!("Sending HTTP request");
    log::info!("########################################################");
    tls_connection
        .write_tls(http_request)
        .expect("Failed to write application data over TLS");

    log::info!("########################################################");
    log::info!("Receiving HTTP response");
    log::info!("########################################################");
    let mut data_from_server = alloc::vec![0u8; IN_BUF_SIZE * 3]; // this is arbitrary

    let total_len = read_command(&mut tls_connection, &mut data_from_server)
        .expect("Failed to read application data over TLS");

    let response = core::str::from_utf8(&data_from_server).unwrap_or("<Invalid UTF-8>");
    log::info!("Total length: {}\n Response: \n {}", total_len, response);

    log::info!("########################################################");
    log::info!("Closing TLS connection");
    log::info!("########################################################");
    tls_connection
        .close_tls()
        .expect("Failed to close TLS connection");

    log::info!("TLS conversation completed.");
}

/// Test function to interact with a command server over TLS
/// The server is expected to send commands and wait for responses.
/// The interaction continues until an "EXIT" command is received.  
/// The server is expected to close the connection after sending the "EXIT" command.
pub fn test_command_server() {
    log::info!("Opening TLS...");

    let mut tls_connection = TlsClient::new(false)
        .connect(
            VsockStream::connect(LOCAL_PORT, REMOTE_PORT, REMOTE_CID)
                .expect("Failed to connect to VsockStream"),
            SERVER_DNS,
        )
        .expect("Failed to create TLS connection");

    log::info!("########################################################");
    log::info!("Completing TLS handshake");
    log::info!("########################################################");
    tls_connection
        .complete_handshake()
        .expect("Failed to complete TLS handshake");

    log::info!("########################################################");
    log::info!("Entering command server read loop");
    log::info!("########################################################");

    let mut data_from_server = alloc::vec![0u8; IN_BUF_SIZE * 3];

    loop {
        log::info!("########################################################");
        log::info!("Waiting for command server input");
        log::info!("########################################################");

        let total_len = read_command(&mut tls_connection, &mut data_from_server)
            .expect("Failed to read application data over TLS");

        if total_len == 0 {
            log::info!("Peer closed the connection, exiting read loop");
            break;
        }

        let response =
            core::str::from_utf8(&data_from_server[..total_len]).unwrap_or("<Invalid UTF-8>");

        log::info!("Received {} bytes:\n{}", total_len, response);
        log::info!("########################################################");
        log::info!("Sending response to command server");
        log::info!("########################################################");

        let response_message = b"Message received\n";
        tls_connection
            .write_tls(response_message)
            .expect("Failed to write application data over TLS");

        if response.contains("EXIT") {
            log::info!("Received EXIT command, exiting read loop");
            break;
        } else {
            log::info!("Received command: {}\n Continue", response);
        }
    }

    log::info!("########################################################");
    log::info!("Closing TLS connection");
    log::info!("########################################################");
    tls_connection
        .close_tls()
        .expect("Failed to close TLS connection");
    log::info!("TLS conversation completed.");
}

fn read_command(tls_connection: &mut TlsConnection, buf: &mut [u8]) -> Result<usize, SvsmError> {
    // read application data record from the server
    // for the moment just one read
    let mut iter_count = 1;
    log::info!("Initial read iteration");
    let mut total_read = 0;
    let partial_read = tls_connection.read_tls(&mut buf[total_read..])?;

    if partial_read == 0 {
        log::info!("No data received from server");
        return Ok(0);
    }

    total_read += partial_read;

    // extract content-length from the HTTP response header
    // for the moment just arbitrary number of reads
    // what if the response header is not complete?

    while iter_count < 1 {
        // should use content-length to determine when to stop
        log::info!("Read iteration {}", iter_count);
        tls_connection
            .read_tls(&mut buf[total_read..])
            .map(|len| {
                if len == 0 {
                    return;
                }
                total_read += len;
            })
            .expect("Failed to read application data over TLS");
        iter_count += 1;
    }

    Ok(total_read)
}
