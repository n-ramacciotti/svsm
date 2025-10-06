// ########################################################
// # Example functions to test the TLS and HTTPS modules  #
// ########################################################

extern crate alloc;

use crate::vsock::virtio_vsock::VsockStream;

use super::constant::IN_BUF_SIZE;
use super::https_peer::HttpsPeer;

const LOCAL_PORT: u32 = 1234;
const REMOTE_PORT: u32 = 12345;
const REMOTE_CID: u64 = 2;
const SERVER_DNS: &str = "localhost";

use super::connection::TlsClient;

/// Example function to test HTTPS connection as a server
pub fn test_https_as_server() {
    // ########################################################
    // Creating HTTPS connection
    // ########################################################
    let mut https_connection = HttpsPeer::connect(
        VsockStream::connect(LOCAL_PORT, REMOTE_PORT, REMOTE_CID)
            .expect("Failed to connect to VsockStream"),
        SERVER_DNS,
        IN_BUF_SIZE * 3,
    )
    .expect("Failed to create HTTPS connection");

    // ########################################################
    // Receiving HTTP request
    // ########################################################
    loop {
        let request = https_connection
            .receive_request()
            .expect("Failed to receive HTTP request");
        log::info!("Request:\n {:?}", request);

        // ########################################################
        // Sending HTTP response
        // ########################################################
        let body_content = b"Hello, World!";
        let content_length = body_content.len();

        let http_response = crate::tls::http::response::HttpResponseBuilder::new()
            .version(Some(1))
            .code(Some(200))
            .reason(Some("OK"))
            .header("Content-Type", "text/html")
            .header("Content-Length", &alloc::format!("{}", content_length))
            .body(body_content.to_vec())
            .build()
            .expect("Failed to build HTTP response");

        log::info!("Sending response:\n {:?}", http_response);

        https_connection
            .send_response(http_response)
            .expect("Failed to send HTTP response");

        if let Some(conn_header) = request.headers().get("Connection") {
            if conn_header.to_lowercase() == "close" {
                log::info!("Connection: close received, breaking the loop");
                break;
            }
        }
    }
    // ########################################################
    // Closing HTTPS connection
    // ########################################################
    https_connection
        .close_connection()
        .expect("Failed to close HTTPS connection");
    // ########################################################
    log::info!("HTTPS conversation completed.");
}

/// Example function to test HTTPS connection as a client
pub fn test_https_as_client() {
    // ########################################################
    // Creating HTTPS connection
    // ########################################################
    let mut https_connection = HttpsPeer::connect(
        VsockStream::connect(LOCAL_PORT, REMOTE_PORT, REMOTE_CID)
            .expect("Failed to connect to VsockStream"),
        SERVER_DNS,
        IN_BUF_SIZE * 3,
    )
    .expect("Failed to create HTTPS connection");

    // ########################################################
    // Sending HTTP request
    // ########################################################
    let http_request = crate::tls::http::request::HttpRequestBuilder::new()
        .method(Some("GET"))
        .path(Some("/hello.html"))
        .version(Some(1))
        .header("Host", "127.0.0.1")
        .header("Connection", "close")
        .body(b"A".to_vec())
        .build()
        .expect("Failed to build HTTP request");

    https_connection
        .send_request(http_request)
        .expect("Failed to send HTTP request");

    // ########################################################
    // Receiving HTTP response
    // ########################################################
    let response = https_connection
        .receive_response()
        .expect("Failed to receive HTTP response");
    log::info!("Response:\n {:?}", response);

    log::info!(
        "Body:\n {}",
        core::str::from_utf8(response.body()).unwrap_or("<Invalid UTF-8>")
    );

    // ########################################################
    // Closing HTTPS connection
    // ########################################################
    https_connection
        .close_connection()
        .expect("Failed to close HTTPS connection");
    // ########################################################
    log::info!("HTTPS conversation completed.");
}

/// Test function to interact with an HTTPS server as a client
/// using direct TLS connection
pub fn test_tls() {
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
