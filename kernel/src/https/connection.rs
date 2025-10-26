extern crate alloc;

use super::http::constants::MAX_HTTP_BUFFER_SIZE;
use super::http::error::HttpError;
use super::http::request::HttpRequest;
use super::http::response::HttpResponse;
use super::http::traits::MessageReceivable;
use super::http::traits::ToBytes;
use crate::error::SvsmError;
use crate::tls::connection::TlsClient;
use crate::tls::connection::TlsConnection;
use crate::tls::error::TlsError;
use crate::tls::MAX_TLS_RECORD_LEN;
use crate::vsock::stream::VsockStream;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct HttpsPeer;

impl HttpsPeer {
    // Maybe it is better to use it directly in httpsconnection
    pub fn connect(
        vsock: VsockStream,
        server_dns: &str,
        buffer_size: usize,
    ) -> Result<HttpsConnection, SvsmError> {
        let mut tls_connection = TlsClient::new(false).connect(vsock, server_dns)?;
        tls_connection.complete_handshake()?;
        if buffer_size == 0 || buffer_size > MAX_HTTP_BUFFER_SIZE {
            return Err(HttpError::BufferSizeError(buffer_size, MAX_HTTP_BUFFER_SIZE).into());
        }
        Ok(HttpsConnection {
            tls_connection,
            buffer: vec![0u8; buffer_size],
            body_start: 0,
            connection_closed: false,
            message_received: false,
            message_sent: false,
            max_buffer_size: buffer_size,
        })
    }
}

#[derive(Debug)]
pub struct HttpsConnection {
    tls_connection: TlsConnection,
    buffer: Vec<u8>,
    body_start: usize,
    connection_closed: bool,
    // No pipelining support for now
    message_received: bool,
    message_sent: bool,
    max_buffer_size: usize,
}

impl HttpsConnection {
    pub fn close_connection(&mut self) -> Result<(), SvsmError> {
        if self.connection_closed {
            return Ok(());
        }
        self.tls_connection.close_tls()?;
        self.connection_closed = true;
        Ok(())
    }

    pub fn send_request(&mut self, req: &HttpRequest) -> Result<(), SvsmError> {
        self.send_message(req)
    }

    pub fn send_response(&mut self, res: &HttpResponse) -> Result<(), SvsmError> {
        self.send_message(res)
    }

    pub fn receive_response(&mut self) -> Result<HttpResponse, SvsmError> {
        self.receive_message::<HttpResponse>()
    }

    pub fn receive_request(&mut self) -> Result<HttpRequest, SvsmError> {
        self.receive_message::<HttpRequest>()
    }

    fn send_message<T: ToBytes>(&mut self, msg: &T) -> Result<(), SvsmError> {
        self.can_send_message()?;
        let message_bytes = msg.to_bytes();
        log::info!("Length of message to send: {}", message_bytes.len());
        for chunk in message_bytes.chunks(MAX_TLS_RECORD_LEN) {
            self.tls_connection.write_tls(chunk)?;
        }
        self.message_sent = true;
        self.message_received = false;
        Ok(())
    }

    fn receive_message<M: MessageReceivable>(&mut self) -> Result<M, SvsmError> {
        self.can_receive_message()?;

        let (headers_length, content_length, builder) = self.parse_http_headers::<M>()?;

        let body_read = if content_length == 0 {
            0
        } else {
            if content_length + headers_length > self.max_buffer_size {
                return Err(HttpError::BufferSizeError(
                    content_length + headers_length,
                    self.max_buffer_size,
                )
                .into());
            }
            self.parse_http_body(content_length, headers_length)?
        };

        if body_read != content_length {
            log::info!(
                "Expected body length {}, but only read {}",
                content_length,
                body_read
            );
        }

        let message = M::get_message_from_parts(
            builder,
            Vec::from(&self.buffer[self.body_start..self.body_start + body_read]),
        )?;

        self.message_received = true;
        self.message_sent = false;
        Ok(message)
    }

    fn can_send_message(&self) -> Result<(), SvsmError> {
        if self.connection_closed {
            return Err(HttpError::ConnectionClosed)?;
        }

        if self.message_sent {
            log::info!("A message has already been sent without receiving a new one");
            return Err(HttpError::ResponseAlreadySent)?;
        }

        Ok(())
    }

    fn can_receive_message(&self) -> Result<(), SvsmError> {
        if self.connection_closed {
            return Err(HttpError::ConnectionClosed)?;
        }

        if self.message_received {
            log::info!("A message has already been received without sending a new one");
            return Err(HttpError::RequestAlreadyReceived)?;
        }

        Ok(())
    }

    fn parse_http_headers<M: MessageReceivable>(
        &mut self,
    ) -> Result<(usize, usize, M::Builder), SvsmError> {
        let mut total_read = 0;
        loop {
            let partial_read = self
                .tls_connection
                .read_tls(&mut self.buffer[total_read..])?;

            if partial_read == 0 {
                log::info!("No more data received from the peer");
                return Err(TlsError::ConnectionClosed.into());
            }

            total_read += partial_read;

            if let Some((body_start, content_length, builder)) =
                M::init_builder_from_headers(&self.buffer[..total_read])?
            {
                self.body_start = body_start;
                return Ok((total_read, content_length, builder));
            }
            log::info!("HTTP message is partial, continuing to read");

            // match M::init_builder_from_headers(&self.buffer[..total_read])? {
            //     Some((body_start, content_length, builder)) => {
            //         self.body_start = body_start;
            //         return Ok((total_read, content_length, builder));
            //     }
            //     None => {
            //         log::info!("HTTP message is partial, continuing to read");
            //     }
            // }
        }
    }

    fn parse_http_body(
        &mut self,
        content_length: usize,
        total_read: usize,
    ) -> Result<usize, SvsmError> {
        log::info!(
            "Content-Length: {}, already read: {}, body starts at: {}",
            content_length,
            total_read,
            self.body_start
        );
        if total_read == self.body_start + content_length {
            return Ok(content_length);
        }
        let to_read = self.body_start + content_length - total_read;
        log::info!("Need to read additional {} bytes for the body", to_read);
        let mut body_read = 0;
        while body_read < to_read {
            let partial_read = self
                .tls_connection
                .read_tls(&mut self.buffer[total_read + body_read..])?;
            if partial_read == 0 {
                break;
            }
            body_read += partial_read;
        }
        Ok(content_length)
    }
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    use super::*;
    use crate::https::http::request::HttpRequestBuilder;
    use crate::testutils::has_test_iorequests;
    use crate::tls::MAX_TLS_RECORD_LEN;

    fn start_tls_server_host() {
        use crate::serial::Terminal;
        use crate::testing::{svsm_test_io, IORequest};

        let sp = svsm_test_io().unwrap();

        sp.put_byte(IORequest::StartTlsServer as u8);

        let _ = sp.get_byte();
    }

    fn get_vsock_stream() -> VsockStream {
        let cid = 2;
        let remote_port = 12346;

        VsockStream::connect(remote_port, cid).expect("Failed to connect to vsock server")
    }

    fn get_https_connection() -> HttpsConnection {
        let servername = "localhost";
        let sock = get_vsock_stream();
        HttpsPeer::connect(sock, servername, MAX_TLS_RECORD_LEN * 2)
            .expect("Failed to create HTTPS connection")
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_https_client() {
        if !has_test_iorequests() {
            return;
        }

        start_tls_server_host();

        let mut https_connection = get_https_connection();

        let http_request = HttpRequestBuilder::new()
            .method(Some("GET"))
            .path(Some("/"))
            .version(Some(1))
            .header("Host", "localhost")
            .header("Connection", "close")
            .body(Vec::new())
            .build()
            .expect("Failed to build HTTP request");

        https_connection
            .send_request(&http_request)
            .expect("Failed to send HTTP request");

        https_connection
            .send_request(&http_request)
            .expect_err("Sending a second request without reading the response should fail");

        let _response = https_connection
            .receive_response()
            .expect("Failed to receive HTTP response");

        https_connection
            .receive_response()
            .expect_err("Receiving a second response without sending a new request should fail");

        https_connection
            .close_connection()
            .expect("Failed to close HTTPS connection");

        https_connection
            .close_connection()
            .expect("A second close should succeed");

        https_connection
            .send_request(&http_request)
            .expect_err("Sending request after closing should fail");

        https_connection
            .receive_response()
            .expect_err("Receiving response after closing should fail");
    }
}
