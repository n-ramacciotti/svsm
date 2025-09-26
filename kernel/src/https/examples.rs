// ########################################################
// # Example functions to test HTTPS modules              #
// ########################################################

extern crate alloc;

use crate::vsock::stream::VsockStream;

use super::connection::HttpsPeer;
use super::http::request::HttpRequestBuilder;
use super::http::response::HttpResponseBuilder;
use crate::tls::MAX_TLS_RECORD_LEN;

const REMOTE_PORT: u32 = 12345;
const REMOTE_CID: u64 = 2;
const SERVER_DNS: &str = "localhost";

/// Example function to test HTTPS connection as a server
pub fn test_https_as_server() {
    // ########################################################
    // Creating HTTPS connection
    // ########################################################
    let mut https_connection = HttpsPeer::connect(
        VsockStream::connect(REMOTE_PORT, REMOTE_CID).expect("Failed to connect to VsockStream"),
        SERVER_DNS,
        2 * MAX_TLS_RECORD_LEN,
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

        let http_response = HttpResponseBuilder::new()
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
            .send_response(&http_response)
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
        VsockStream::connect(REMOTE_PORT, REMOTE_CID).expect("Failed to connect to VsockStream"),
        SERVER_DNS,
        2 * MAX_TLS_RECORD_LEN,
    )
    .expect("Failed to create HTTPS connection");

    // ########################################################
    // Sending HTTP request
    // ########################################################
    let http_request = HttpRequestBuilder::new()
        .method(Some("GET"))
        .path(Some("/hello.html"))
        .version(Some(1))
        .header("Host", "127.0.0.1")
        .header("Connection", "close")
        .body(b"A".to_vec())
        .build()
        .expect("Failed to build HTTP request");

    https_connection
        .send_request(&http_request)
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
