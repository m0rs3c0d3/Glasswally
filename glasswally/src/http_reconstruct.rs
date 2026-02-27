// glasswally/src/http_reconstruct.rs
//
// HTTP request reconstruction from raw SSL plaintext captures.
//
// SSL events arrive as raw byte chunks — one ssl_write call may contain
// a partial HTTP request, or multiple requests. We reassemble them here
// into structured HttpRequest objects, then extract:
//   - Header names in arrival order (for header fingerprint)
//   - Authorization / x-api-key (→ account_id)
//   - Request body JSON (→ model, prompt, token_count)
//   - User-Agent (for JA3 mismatch detection)

use std::collections::HashMap;

use crate::events::{HttpRequest, SslCapture, SslDirection};

// ── HTTP parser ───────────────────────────────────────────────────────────────

/// Reconstruct an HTTP request from a plaintext SSL capture.
/// Returns None if the capture doesn't look like an HTTP request.
pub fn reconstruct(capture: &SslCapture) -> Option<HttpRequest> {
    if capture.direction != SslDirection::Write {
        return None; // Only parse outbound (request) data
    }

    let text = &capture.text;

    // Quick check: must start with HTTP method
    if !looks_like_http_request(text) {
        return None;
    }

    parse_http_request(text, capture)
}

fn looks_like_http_request(text: &str) -> bool {
    text.starts_with("GET ")
        || text.starts_with("POST ")
        || text.starts_with("PUT ")
        || text.starts_with("DELETE ")
        || text.starts_with("PATCH ")
        || text.starts_with("HEAD ")
}

fn parse_http_request(text: &str, capture: &SslCapture) -> Option<HttpRequest> {
    // Split headers from body at \r\n\r\n
    let (header_section, body) = if let Some(idx) = text.find("\r\n\r\n") {
        (&text[..idx], text[idx + 4..].to_string())
    } else if let Some(idx) = text.find("\n\n") {
        (&text[..idx], text[idx + 2..].to_string())
    } else {
        (text, String::new())
    };

    let mut lines = header_section.lines();

    // Request line: METHOD /path HTTP/version
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    // Parse headers — PRESERVE ORDER (critical for fingerprinting)
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let value = line[colon + 1..].trim().to_string();
            headers.push((name, value));
        }
    }

    // Extract specific headers
    let _user_agent = header_value(&headers, "user-agent").unwrap_or_default();
    let auth = header_value(&headers, "authorization")
        .or_else(|| header_value(&headers, "x-api-key"))
        .unwrap_or_default();
    let content_type = header_value(&headers, "content-type").unwrap_or_default();

    // Derive account_id from auth header
    // In Anthropic's API: Authorization: Bearer sk-ant-...
    // We hash it for privacy — we don't need the raw key
    let account_id = if !auth.is_empty() {
        Some(derive_account_id(&auth))
    } else {
        capture.account_id.clone()
    };

    // Extract model + prompt from JSON body
    let (model, prompt, token_count) = if content_type.contains("json") && !body.is_empty() {
        extract_from_json_body(&body)
    } else {
        (None, None, None)
    };

    // Extract model from path if not in body
    // Anthropic API: POST /v1/messages, model in body
    // OpenAI compat: POST /v1/chat/completions
    let model = model.or_else(|| extract_model_from_path(&path));

    Some(HttpRequest {
        conn_key: capture.conn_key.clone(),
        method,
        path,
        headers,
        body,
        timestamp: capture.timestamp,
        account_id,
        model,
        prompt,
        token_count,
    })
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == name)
        .map(|(_, v)| v.clone())
}

/// Derive a stable account identifier from the API key.
/// We hash it so we never store raw keys.
fn derive_account_id(auth: &str) -> String {
    use sha2::{Digest, Sha256};
    // Extract the key part (after "Bearer " if present)
    let key = auth.trim_start_matches("Bearer ").trim();
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    // First 16 hex chars is enough for unique identification
    hex::encode(&hasher.finalize()[..8])
}

fn extract_from_json_body(body: &str) -> (Option<String>, Option<String>, Option<u32>) {
    // Fast path: try serde_json
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        let model = v["model"].as_str().map(|s| s.to_string());

        // Extract prompt from Anthropic messages format:
        // {"messages": [{"role": "user", "content": "..."}]}
        let prompt = v["messages"]
            .as_array()
            .and_then(|msgs| {
                msgs.iter()
                    .rev()
                    .find(|m| m["role"] == "user")
                    .and_then(|m| m["content"].as_str())
                    .map(|s| s.to_string())
            })
            // Also check direct "prompt" field (legacy)
            .or_else(|| v["prompt"].as_str().map(|s| s.to_string()));

        // max_tokens as a proxy for expected response size
        let token_count = v["max_tokens"].as_u64().map(|t| t as u32);

        return (model, prompt, token_count);
    }

    // Slow path: regex-free text extraction for malformed JSON
    let model = extract_json_string(body, "model");
    let prompt = None; // Don't attempt on malformed JSON

    (model, prompt, None)
}

fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":", key);
    let start = text.find(&search)? + search.len();
    let rest = text[start..].trim_start();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

fn extract_model_from_path(path: &str) -> Option<String> {
    // /v1/models/claude-3-5-sonnet → claude-3-5-sonnet
    if let Some(models_pos) = path.find("/models/") {
        let after = &path[models_pos + 8..];
        let end = after.find('/').unwrap_or(after.len());
        if !after[..end].is_empty() {
            return Some(after[..end].to_string());
        }
    }
    None
}

// ── Stream reassembler ────────────────────────────────────────────────────────
// Some HTTP requests span multiple SSL write calls.
// We buffer per-connection until we see a complete request.

pub struct StreamReassembler {
    /// Per-connection partial buffers
    buffers: HashMap<u64, String>, // key = pid<<32|fd
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Feed a raw SSL capture. Returns a complete HttpRequest if one is ready.
    pub fn feed(&mut self, capture: SslCapture) -> Option<HttpRequest> {
        if capture.direction != SslDirection::Write {
            return None;
        }

        let key = ((capture.pid as u64) << 32) | ((capture.fd as u64) & 0xFFFFFFFF);

        // Check if this is a fresh request (starts with HTTP method)
        if looks_like_http_request(&capture.text) {
            // New request — replace any partial buffer
            self.buffers.insert(key, capture.text.clone());
        } else {
            // Continuation — append to existing buffer
            let buf = self.buffers.entry(key).or_default();
            buf.push_str(&capture.text);
        }

        // Try to parse whatever we have
        let buf = self.buffers.get(&key)?;
        if is_complete_http_request(buf) {
            let buf_clone = buf.clone();
            self.buffers.remove(&key);
            parse_http_request(&buf_clone, &capture)
        } else {
            None
        }
    }

    /// Flush a connection's buffer (called on tcp_close).
    pub fn flush(&mut self, pid: u32, fd: i32) -> Option<String> {
        let key = ((pid as u64) << 32) | ((fd as u64) & 0xFFFFFFFF);
        self.buffers.remove(&key)
    }
}

fn is_complete_http_request(text: &str) -> bool {
    // Has headers + body separator
    let has_separator = text.contains("\r\n\r\n") || text.contains("\n\n");
    if !has_separator {
        return false;
    }

    // If POST/PUT, check Content-Length vs actual body length
    if let Some(cl_str) = extract_header_value(text, "content-length") {
        if let Ok(cl) = cl_str.parse::<usize>() {
            let body_start = text
                .find("\r\n\r\n")
                .map(|i| i + 4)
                .or_else(|| text.find("\n\n").map(|i| i + 2))
                .unwrap_or(text.len());
            return text.len() >= body_start + cl;
        }
    }
    has_separator
}

fn extract_header_value<'a>(text: &'a str, header: &str) -> Option<&'a str> {
    let search = format!("{}: ", header.to_lowercase());
    let lower = text.to_lowercase();
    let start = lower.find(&search)? + search.len();
    let rest = &text[start..];
    let end = rest
        .find('\r')
        .or_else(|| rest.find('\n'))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

impl Default for StreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}
