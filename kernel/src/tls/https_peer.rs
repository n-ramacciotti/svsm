extern crate alloc;

use super::http::response::{HttpResponse, HttpResponseBuilder};
use crate::error::SvsmError;
use crate::tls::connection::TlsClient;
use crate::tls::connection::TlsConnection;
use crate::tls::error::TlsError;
use crate::tls::http::error::HttpError;
use crate::tls::http::request::HttpRequest;
use crate::tls::http::request::HttpRequestBuilder;
use crate::vsock::virtio_vsock::VsockStream;
use alloc::vec;
use alloc::vec::Vec;
use httparse::Header;
use httparse::{Request as ParsedRequest, Response as ParsedResponse, EMPTY_HEADER};

// todo: introduce traits to generalize between request and response

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
        Ok(HttpsConnection {
            tls_connection,
            buffer: vec![0u8; buffer_size],
            body_start: 0,
        })
    }
}

#[derive(Debug)]
pub struct HttpsConnection {
    tls_connection: TlsConnection,
    buffer: Vec<u8>,
    body_start: usize,
}
// todo: add state to see if the peer closed the connection

impl HttpsConnection {
    pub fn close_connection(&mut self) -> Result<(), SvsmError> {
        self.tls_connection.close_tls()?;
        Ok(())
    }

    pub fn send_request(&mut self, req: HttpRequest) -> Result<(), SvsmError> {
        let request_bytes = req.to_bytes();
        log::info!("Length of request to send: {}", request_bytes.len());
        self.tls_connection.write_tls(&request_bytes)?;
        Ok(())
    }

    pub fn send_response(&mut self, res: HttpResponse) -> Result<(), SvsmError> {
        let response_bytes = res.to_bytes();
        log::info!("Length of response to send: {}", response_bytes.len());
        self.tls_connection.write_tls(&response_bytes)?;
        Ok(())
    }

    pub fn receive_response(&mut self) -> Result<HttpResponse, SvsmError> {
        let (headers_length, content_length, builder) = self.parse_http_headers_response()?;
        if content_length == 0 {
            return Err(TlsError::from(HttpError::MissingHeader("Content-Length")))?;
        }

        // todo: check buffer size

        let body_read = self.parse_http_body(content_length, headers_length)?;
        if body_read != content_length {
            log::info!(
                "Expected body length {}, but only read {}",
                content_length,
                body_read
            );
        }

        let response = builder
            .body(Vec::from(
                &self.buffer[self.body_start..self.body_start + body_read],
            ))
            .build()
            .map_err(TlsError::from)?;

        Ok(response)
    }

    pub fn receive_request(&mut self) -> Result<HttpRequest, SvsmError> {
        let (headers_length, content_length, builder) = self.parse_http_headers_request()?;
        if content_length == 0 {
            return Err(TlsError::from(HttpError::MissingHeader("Content-Length")))?;
        }

        // todo: check buffer size

        let body_read = self.parse_http_body(content_length, headers_length)?;
        if body_read != content_length {
            log::info!(
                "Expected body length {}, but only read {}",
                content_length,
                body_read
            );
        }

        let response = builder
            .body(Vec::from(
                &self.buffer[self.body_start..self.body_start + body_read],
            ))
            .build()
            .map_err(TlsError::from)?;

        Ok(response)
    }

    fn parse_http_headers_response(
        &mut self,
    ) -> Result<(usize, usize, HttpResponseBuilder), SvsmError> {
        let mut total_read = 0;
        loop {
            let partial_read = self
                .tls_connection
                .read_tls(&mut self.buffer[total_read..])?;

            if partial_read == 0 {
                log::info!("No more data received from the peer");
                return Err(SvsmError::Tls(TlsError::GenericError));
            }

            total_read += partial_read;

            let mut headers = [EMPTY_HEADER; 16];
            let mut res = ParsedResponse::new(&mut headers);

            match res.parse(&self.buffer[..total_read]) {
                Ok(httparse::Status::Complete(body_start)) => {
                    log::info!("HTTP response parsed successfully");
                    // TODO: handle cases where Content-Length is missing?
                    let content_length = Self::extract_content_length(res.headers).ok_or(
                        SvsmError::Tls(TlsError::Http(HttpError::MissingHeader("Content-Length"))),
                    )?;
                    self.body_start = body_start;
                    let builder = Self::build_http_response(&res).map_err(SvsmError::from)?;
                    return Ok((total_read, content_length, builder));
                }
                Ok(httparse::Status::Partial) => {
                    log::info!("HTTP response is partial, continuing to read");
                }
                Err(e) => {
                    log::info!("Failed to parse HTTP response: {:?}", e);
                    return Err(SvsmError::Tls(TlsError::Http(HttpError::GenericError)));
                }
            }
        }
    }

    fn parse_http_headers_request(
        &mut self,
    ) -> Result<(usize, usize, HttpRequestBuilder), SvsmError> {
        let mut total_read = 0;
        loop {
            let partial_read = self
                .tls_connection
                .read_tls(&mut self.buffer[total_read..])?;

            if partial_read == 0 {
                // todo: Connection closed
                log::info!("No more data received from the peer");
                return Err(SvsmError::Tls(TlsError::GenericError));
            }

            total_read += partial_read;

            let mut headers = [EMPTY_HEADER; 16];

            let mut req = ParsedRequest::new(&mut headers);
            match req.parse(&self.buffer[..total_read]) {
                Ok(httparse::Status::Complete(body_start)) => {
                    log::info!("HTTP request parsed successfully");
                    // todo: handle cases where Content-Length is missing?
                    let content_length = Self::extract_content_length(req.headers).ok_or(
                        SvsmError::Tls(TlsError::Http(HttpError::MissingHeader("Content-Length"))),
                    )?;
                    let builder = Self::build_http_request(&req).map_err(SvsmError::from)?;
                    self.body_start = body_start;
                    return Ok((total_read, content_length, builder));
                }
                Ok(httparse::Status::Partial) => {
                    log::info!("HTTP request is partial, continuing to read");
                }
                Err(e) => {
                    log::info!("Failed to parse HTTP request: {:?}", e);
                    return Err(SvsmError::Tls(TlsError::Http(HttpError::GenericError)));
                }
            }
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

    fn build_http_response(res: &ParsedResponse<'_, '_>) -> Result<HttpResponseBuilder, TlsError> {
        let builder = HttpResponseBuilder::new()
            .code(res.code)
            .reason(res.reason)
            .version(res.version);

        let builder = Self::build_headers_response(builder, res.headers)?;

        Ok(builder)
    }

    fn build_http_request(req: &ParsedRequest<'_, '_>) -> Result<HttpRequestBuilder, TlsError> {
        let builder = HttpRequestBuilder::new()
            .method(req.method)
            .path(req.path)
            .version(req.version);

        let builder = Self::build_headers_request(builder, req.headers)?;

        Ok(builder)
    }

    fn build_headers_request(
        mut builder: HttpRequestBuilder,
        headers: &[Header<'_>],
    ) -> Result<HttpRequestBuilder, TlsError> {
        for header in headers.iter() {
            if let Ok(header_name) = core::str::from_utf8(header.name.as_bytes()) {
                if let Ok(header_value) = core::str::from_utf8(header.value) {
                    builder = builder.header(header_name, header_value);
                }
            }
        }
        Ok(builder)
    }

    fn build_headers_response(
        mut builder: HttpResponseBuilder,
        headers: &[Header<'_>],
    ) -> Result<HttpResponseBuilder, TlsError> {
        for header in headers.iter() {
            if let Ok(header_name) = core::str::from_utf8(header.name.as_bytes()) {
                if let Ok(header_value) = core::str::from_utf8(header.value) {
                    builder = builder.header(header_name, header_value);
                }
            }
        }
        Ok(builder)
    }

    fn extract_content_length(headers: &[Header<'_>]) -> Option<usize> {
        for header in headers.iter() {
            if header.name.eq_ignore_ascii_case("Content-Length") {
                if let Ok(content_length_str) = core::str::from_utf8(header.value) {
                    if let Ok(content_length) = content_length_str.parse::<usize>() {
                        return Some(content_length);
                    }
                }
            }
        }
        None
    }
}
