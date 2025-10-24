extern crate alloc;

use crate::tls::http::error::HttpError;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

#[derive(Debug)]
pub struct HttpRequest {
    method: Option<String>,
    path: Option<String>,
    version: Option<u8>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
    pub fn version(&self) -> Option<u8> {
        self.version
    }
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut request_line = String::new();
        if let (Some(method), Some(path), Some(version)) = (&self.method, &self.path, self.version)
        {
            request_line.push_str(&format!("{} {} HTTP/1.{}\r\n", method, path, version));
        } else {
            // Default to GET / HTTP/1.1
            request_line.push_str("GET / HTTP/1.1\r\n");
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

        let mut request_bytes = Vec::new();
        request_bytes.extend_from_slice(request_line.as_bytes());
        request_bytes.extend_from_slice(headers.as_bytes());
        request_bytes.extend_from_slice(&self.body);

        request_bytes
    }
}

#[derive(Debug)]
pub struct HttpRequestBuilder {
    method: Option<String>,
    path: Option<String>,
    version: Option<u8>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequestBuilder {
    pub fn new() -> Self {
        Self {
            method: None,
            path: None,
            version: None,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn method(mut self, method: Option<&str>) -> Self {
        self.method = method.map(String::from);
        self
    }
    pub fn path(mut self, path: Option<&str>) -> Self {
        self.path = path.map(String::from);
        self
    }
    pub fn version(mut self, version: Option<u8>) -> Self {
        self.version = version;
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
    pub fn build(self) -> Result<HttpRequest, HttpError> {
        Ok(HttpRequest {
            method: self.method,
            path: self.path,
            version: self.version,
            headers: self.headers,
            body: self.body,
        })
    }
}

impl Default for HttpRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}
