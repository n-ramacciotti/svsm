/// Extracts the Content-Length from HTTP headers
pub fn extract_content_length(headers: &[httparse::Header<'_>]) -> Option<usize> {
    for header in headers {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            if let Ok(value_str) = core::str::from_utf8(header.value) {
                if let Ok(length) = value_str.trim().parse::<usize>() {
                    return Some(length);
                }
            }
        }
    }
    None
}
