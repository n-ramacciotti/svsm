extern crate alloc;

use super::constants::MAX_HTTP_HEADERS;
use super::error::HttpError;
use super::traits::MessageReceivable;
use super::traits::ToBytes;
use super::utils::extract_content_length;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;
use httparse::Response as ParsedResponse;
use httparse::Status;
use httparse::EMPTY_HEADER;

#[derive(Debug)]
pub struct HttpResponse {
    version: Option<u8>,
    code: Option<u16>,
    reason: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn version(&self) -> Option<u8> {
        self.version
    }
    pub fn code(&self) -> Option<u16> {
        self.code
    }
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut status_line = String::new();
        if let (Some(version), Some(code), Some(reason)) = (self.version, self.code, &self.reason) {
            status_line.push_str(&format!("HTTP/1.{} {} {}\r\n", version, code, reason));
        } else {
            // Default to HTTP/1.1 200 OK
            status_line.push_str("HTTP/1.1 200 OK\r\n");
        }

        let mut headers = String::new();
        for (key, value) in &self.headers {
            headers.push_str(&format!("{}: {}\r\n", key, value));
        }

        let content_length = self.body.len();
        if content_length > 0 && !self.headers.contains_key("Content-Length") {
            headers.push_str(&format!("Content-Length: {}\r\n", content_length));
        }

        headers.push_str("\r\n");

        let mut response_bytes = Vec::new();
        response_bytes.extend_from_slice(status_line.as_bytes());
        response_bytes.extend_from_slice(headers.as_bytes());
        response_bytes.extend_from_slice(&self.body);

        response_bytes
    }
}

#[derive(Debug, Default)]
pub struct HttpResponseBuilder {
    version: Option<u8>,
    code: Option<u16>,
    reason: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponseBuilder {
    pub fn new() -> Self {
        Self {
            version: Some(1),
            code: Some(200),
            reason: Some(String::from("OK")),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn version(mut self, version: Option<u8>) -> Self {
        self.version = version;
        self
    }

    pub fn code(mut self, code: Option<u16>) -> Self {
        self.code = code;
        self
    }

    pub fn reason(mut self, reason: Option<&str>) -> Self {
        self.reason = reason.map(String::from);
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(String::from(name), String::from(value));
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn build(self) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            version: self.version,
            code: self.code,
            reason: self.reason,
            headers: self.headers,
            body: self.body,
        })
    }
}

impl ToBytes for HttpResponse {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl MessageReceivable for HttpResponse {
    type Builder = HttpResponseBuilder;

    fn init_builder_from_headers(
        buf: &[u8],
    ) -> Result<Option<(usize, usize, Self::Builder)>, HttpError> {
        let mut headers = [EMPTY_HEADER; MAX_HTTP_HEADERS];
        let mut res = ParsedResponse::new(&mut headers);
        match res.parse(buf)? {
            Status::Complete(body_start) => {
                log::info!("HTTP response parsed successfully");
                let content_length = extract_content_length(res.headers).unwrap_or(0);
                let mut builder = HttpResponseBuilder::new()
                    .version(res.version)
                    .code(res.code)
                    .reason(res.reason);
                for header in res.headers {
                    if let Ok(value_str) = core::str::from_utf8(header.value) {
                        builder = builder.header(header.name, value_str);
                    }
                }

                Ok(Some((body_start, content_length, builder)))
            }
            Status::Partial => Ok(None),
        }
        // match res.parse(buf)? {
        //     Ok(httparse::Status::Complete(body_start)) => {
        //         log::info!("HTTP response parsed successfully");
        //         let content_length = extract_content_length(res.headers).unwrap_or(0);
        //         let mut builder = HttpResponseBuilder::new()
        //             .version(res.version)
        //             .code(res.code)
        //             .reason(res.reason);
        //         for header in res.headers {
        //             if let Ok(value_str) = core::str::from_utf8(header.value) {
        //                 builder = builder.header(header.name, value_str);
        //             }
        //         }

        //         Ok(Some((body_start, content_length, builder)))
        //     }
        //     Ok(httparse::Status::Partial) => Ok(None),
        //     Err(e) => {
        //         log::info!("Failed to parse HTTP response: {:?}", e);
        //         Err(HttpError::GenericError)
        //     }
        // }
    }

    fn get_message_from_parts(builder: Self::Builder, body: Vec<u8>) -> Result<Self, HttpError> {
        builder.body(body).build()
    }
}
