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
use httparse::Request as ParsedRequest;
use httparse::Status;
use httparse::EMPTY_HEADER;

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

    fn to_bytes(&self) -> Vec<u8> {
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

#[derive(Debug, Default)]
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

impl ToBytes for HttpRequest {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl MessageReceivable for HttpRequest {
    type Builder = HttpRequestBuilder;

    fn init_builder_from_headers(
        buf: &[u8],
    ) -> Result<Option<(usize, usize, Self::Builder)>, HttpError> {
        let mut headers = [EMPTY_HEADER; MAX_HTTP_HEADERS];
        let mut req = ParsedRequest::new(&mut headers);
        match req.parse(buf)? {
            Status::Complete(body_start) => {
                log::info!("HTTP request parsed successfully");
                let content_length = extract_content_length(req.headers).unwrap_or(0);
                let mut builder = Self::Builder::new()
                    .method(req.method)
                    .path(req.path)
                    .version(req.version);

                for header in req.headers.iter() {
                    if let Ok(header_name) = core::str::from_utf8(header.name.as_bytes()) {
                        if let Ok(header_value) = core::str::from_utf8(header.value) {
                            builder = builder.header(header_name, header_value);
                        }
                    }
                }
                Ok(Some((body_start, content_length, builder)))
            }
            Status::Partial => Ok(None),
        }
        // match req.parse(buf) {
        //     Ok(httparse::Status::Complete(body_start)) => {
        //         log::info!("HTTP request parsed successfully");
        //         let content_length = extract_content_length(req.headers).unwrap_or(0);
        //         let mut builder = Self::Builder::new()
        //             .method(req.method)
        //             .path(req.path)
        //             .version(req.version);

        //         for header in req.headers.iter() {
        //             if let Ok(header_name) = core::str::from_utf8(header.name.as_bytes()) {
        //                 if let Ok(header_value) = core::str::from_utf8(header.value) {
        //                     builder = builder.header(header_name, header_value);
        //                 }
        //             }
        //         }
        //         Ok(Some((body_start, content_length, builder)))
        //     }
        //     Ok(httparse::Status::Partial) => Ok(None),
        //     Err(e) => {
        //         log::info!("Failed to parse HTTP request: {:?}", e);
        //         Err(HttpError::GenericError)
        //     }
        // }
    }

    fn get_message_from_parts(builder: Self::Builder, body: Vec<u8>) -> Result<Self, HttpError> {
        builder.body(body).build()
    }
}
