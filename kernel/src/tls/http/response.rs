extern crate alloc;

use crate::tls::http::error::HttpError;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

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

    pub fn to_bytes(&self) -> Vec<u8> {
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

#[derive(Debug)]
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

impl Default for HttpResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}
