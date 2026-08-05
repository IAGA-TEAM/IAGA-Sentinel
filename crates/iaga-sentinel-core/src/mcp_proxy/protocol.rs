use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::AsyncBufReadExt;

/// JSON-RPC 2.0 request (MCP transport layer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// MCP tools/call params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: HashMap<String, serde_json::Value>,
}

/// MCP tools/list result item
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<serde_json::Value>, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }

    pub fn error_with_data(
        id: Option<serde_json::Value>,
        code: i64,
        message: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: Some(data),
            }),
        }
    }
}

// ── Bounded line reading for the stdio planes ──

/// Maximum bytes in one JSON-RPC line on the stdio planes.
///
/// The HTTP plane is capped at 2 MiB by axum's default body limit. The stdio
/// planes had no cap at all: `Lines::next_line` grows its buffer until a
/// newline arrives, so a peer that sends a gigabyte without one buffers a
/// gigabyte. This is the only place Sentinel sits INSIDE a protocol rather than
/// beside it, and it was the least bounded. Matching the HTTP number keeps the
/// two planes agreeing instead of each having its own accident.
pub const MAX_LINE_BYTES: usize = 2 * 1024 * 1024;

/// A `tokio::io::Lines` that refuses a line longer than `max`.
///
/// Cancel-safe, like the `Lines` it replaces — which matters because the proxy
/// reads inside a `tokio::select!` that drops the losing future. Partial input
/// lives in `self.buf` across calls, and the only `.await` is `fill_buf`, which
/// inspects the reader's buffer without consuming it; everything that mutates
/// state after it is synchronous, so there is no await point at which bytes can
/// be lost.
pub struct CappedLines<R> {
    reader: R,
    buf: Vec<u8>,
    max: usize,
}

impl<R: tokio::io::AsyncBufRead + Unpin> CappedLines<R> {
    pub fn new(reader: R, max: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            max,
        }
    }

    /// `Ok(None)` at end of input.
    ///
    /// A line over the cap is an `InvalidData` error, not a truncation: handing
    /// the JSON-RPC parser the first 2 MiB of a longer frame would feed it a
    /// different message than the peer sent, which is worse than refusing.
    pub async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        loop {
            // Scope the borrow of `self.reader` so `consume` can take it back.
            let (complete, taken) = {
                let available = self.reader.fill_buf().await?;
                if available.is_empty() {
                    // EOF. A trailing fragment without a newline is still a line.
                    return Ok(if self.buf.is_empty() {
                        None
                    } else {
                        Some(take_line(&mut self.buf))
                    });
                }
                match available.iter().position(|b| *b == b'\n') {
                    Some(i) => {
                        self.buf.extend_from_slice(&available[..i]);
                        (true, i + 1)
                    }
                    None => {
                        self.buf.extend_from_slice(available);
                        (false, available.len())
                    }
                }
            };
            self.reader.consume(taken);

            // Checked BEFORE the `complete` branch, and this ordering is the
            // whole point: `BufReader` hands back up to 8 KiB at a time, so an
            // over-long line whose newline lands inside the same fill would
            // otherwise be returned intact — the cap only ever firing for lines
            // that arrive in more than one chunk. Caught by
            // `an_over_long_line_never_returns_partial_content`.
            if self.buf.len() > self.max {
                let seen = self.buf.len();
                self.buf.clear();
                self.buf.shrink_to_fit();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "JSON-RPC line exceeds the {} byte cap ({seen} bytes)",
                        self.max
                    ),
                ));
            }
            if complete {
                return Ok(Some(take_line(&mut self.buf)));
            }
        }
    }
}

fn take_line(buf: &mut Vec<u8>) -> String {
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    let line = String::from_utf8_lossy(buf).into_owned();
    buf.clear();
    line
}

#[cfg(test)]
mod capped_lines_tests {
    use super::*;
    use tokio::io::BufReader;

    fn reader(bytes: &'static [u8]) -> CappedLines<BufReader<&'static [u8]>> {
        CappedLines::new(BufReader::new(bytes), 64)
    }

    #[tokio::test]
    async fn ordinary_lines_round_trip_unchanged() {
        let mut r = reader(b"{\"a\":1}\n{\"b\":2}\n");
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("{\"a\":1}"));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("{\"b\":2}"));
        assert_eq!(r.next_line().await.unwrap(), None, "clean EOF");
    }

    #[tokio::test]
    async fn crlf_is_stripped_and_a_final_fragment_still_counts() {
        let mut r = reader(b"one\r\ntwo");
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("one"));
        assert_eq!(
            r.next_line().await.unwrap().as_deref(),
            Some("two"),
            "a trailing fragment with no newline is still a line at EOF"
        );
    }

    /// The regression. Before the cap, a peer that never sent a newline made
    /// `Lines::next_line` grow its buffer without bound — the stdio planes were
    /// the only unbounded read surface, while HTTP stops at 2 MiB.
    #[tokio::test]
    async fn a_line_over_the_cap_is_refused_rather_than_buffered() {
        // 200 bytes, no newline, against a 64-byte cap.
        let mut r = reader(&[b'x'; 200]);
        let err = r
            .next_line()
            .await
            .expect_err("an over-long line must be an error, not a value");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("exceeds"),
            "the error must say why: {err}"
        );
    }

    /// Truncation would be worse than refusal: it hands the JSON-RPC parser a
    /// different message than the peer sent. This pins that we never return a
    /// short read for an over-long line.
    #[tokio::test]
    async fn an_over_long_line_never_returns_partial_content() {
        let mut long = vec![b'x'; 200];
        long.push(b'\n');
        let leaked: &'static [u8] = Box::leak(long.into_boxed_slice());
        let mut r = CappedLines::new(BufReader::new(leaked), 64);
        assert!(
            r.next_line().await.is_err(),
            "a 200-byte line under a 64-byte cap must not come back as a value"
        );
    }
}
