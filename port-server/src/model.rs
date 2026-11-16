//! A bounded, host-side OpenAI-compatible client. This does not implement AG-UI.
//! The base URL is trusted administrator configuration, never a browser-supplied URL.
use reqwest::{Client, Response, Url};
use serde_json::Value;
use std::{fmt, time::Duration};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const MAX_REQUEST: usize = 1024 * 1024;
const MAX_LINE: usize = 256 * 1024;
const MAX_EVENT: usize = 512 * 1024;
const MAX_STREAM: usize = 16 * 1024 * 1024;

/// Select only an unambiguous model; multiple returned models require an
/// explicit choice instead of silently routing a conversation elsewhere.
pub fn single_model_id(value: &Value) -> Result<String, ModelError> {
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or(ModelError::Protocol("model list is missing data array"))?;
    if data.len() != 1 {
        return Err(ModelError::Protocol(
            "automatic selection requires exactly one model",
        ));
    }
    data[0]
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty() && id.len() <= 200 && !id.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(ModelError::Protocol("invalid model identifier"))
}

#[derive(Debug)]
pub enum ModelError {
    InvalidConfiguration(&'static str),
    InvalidRequest(&'static str),
    Transport(reqwest::Error),
    HttpStatus(reqwest::StatusCode),
    Protocol(&'static str),
    Cancelled,
    ConsumerClosed,
}
impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(s) | Self::InvalidRequest(s) | Self::Protocol(s) => {
                f.write_str(s)
            }
            Self::Transport(_) => f.write_str("model transport failed or timed out"),
            Self::HttpStatus(s) => write!(f, "model server returned HTTP {s}"),
            Self::Cancelled => f.write_str("model request cancelled"),
            Self::ConsumerClosed => f.write_str("model stream consumer closed"),
        }
    }
}
impl std::error::Error for ModelError {}
impl From<reqwest::Error> for ModelError {
    fn from(e: reqwest::Error) -> Self {
        Self::Transport(e)
    }
}

#[derive(Clone)]
pub struct ModelClient {
    client: Client,
    base: Url,
}

impl ModelClient {
    /// `base` is an administrator-configured API base, e.g. http://127.0.0.1:8081/v1/.
    /// The total timeout also bounds streams. Redirects are disabled to prevent URL changes.
    pub fn new(
        base: &str,
        connect_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, ModelError> {
        let mut base = Url::parse(base)
            .map_err(|_| ModelError::InvalidConfiguration("invalid model API URL"))?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(ModelError::InvalidConfiguration(
                "model API URL must be an HTTP(S) base URL without credentials, query or fragment",
            ));
        }
        if connect_timeout.is_zero() || total_timeout.is_zero() {
            return Err(ModelError::InvalidConfiguration(
                "model timeouts must be positive",
            ));
        }
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(total_timeout)
            .pool_idle_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(1)
            .tcp_nodelay(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self { client, base })
    }
    fn endpoint(&self, path: &str) -> Result<Url, ModelError> {
        self.base
            .join(path)
            .map_err(|_| ModelError::InvalidConfiguration("invalid model API endpoint"))
    }
    pub async fn models(&self, cancel: &CancellationToken) -> Result<Value, ModelError> {
        let req = self.client.get(self.endpoint("models")?).send();
        let mut response = tokio::select! {
            _ = cancel.cancelled() => return Err(ModelError::Cancelled),
            result = req => result?,
        };
        check_status(&response)?;
        let mut data = Vec::new();
        loop {
            let chunk = tokio::select! {
                _ = cancel.cancelled() => return Err(ModelError::Cancelled),
                result = response.chunk() => result?,
            };
            let Some(chunk) = chunk else { break };
            if data.len().saturating_add(chunk.len()) > MAX_RESPONSE {
                return Err(ModelError::Protocol("model list exceeds size limit"));
            }
            data.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&data)
            .map_err(|_| ModelError::Protocol("invalid model list JSON"))?;
        if !value.get("data").is_some_and(Value::is_array) {
            return Err(ModelError::Protocol("model list is missing data array"));
        }
        Ok(value)
    }
    /// Forward parsed OpenAI-compatible streaming JSON chunks to a bounded consumer.
    /// The caller owns request construction, authorization, tool validation and AG-UI translation.
    /// Cancellation or receiver closure aborts the HTTP request and no automatic retry is made.
    pub async fn stream_chat(
        &self,
        mut request: Value,
        output: mpsc::Sender<Value>,
        cancel: &CancellationToken,
    ) -> Result<(), ModelError> {
        let obj = request.as_object_mut().ok_or(ModelError::InvalidRequest(
            "chat request must be a JSON object",
        ))?;
        obj.insert("stream".into(), Value::Bool(true));
        let payload = serde_json::to_vec(&request)
            .map_err(|_| ModelError::InvalidRequest("cannot serialize chat request"))?;
        if payload.len() > MAX_REQUEST {
            return Err(ModelError::InvalidRequest(
                "chat request exceeds size limit",
            ));
        }
        let pending = self
            .client
            .post(self.endpoint("chat/completions")?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(payload)
            .send();
        let mut response = tokio::select! {
            _ = cancel.cancelled() => return Err(ModelError::Cancelled),
            _ = output.closed() => return Err(ModelError::ConsumerClosed),
            result = pending => result?,
        };
        check_status(&response)?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if !content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("text/event-stream")
        {
            return Err(ModelError::Protocol(
                "model response is not an event stream",
            ));
        }
        let mut parser = SseParser::default();
        let mut total = 0usize;
        loop {
            let chunk = tokio::select! {
                _ = cancel.cancelled() => return Err(ModelError::Cancelled),
                _ = output.closed() => return Err(ModelError::ConsumerClosed),
                result = response.chunk() => result?,
            };
            let Some(chunk) = chunk else {
                return Err(ModelError::Protocol("model stream ended without [DONE]"));
            };
            total = total.saturating_add(chunk.len());
            if total > MAX_STREAM {
                return Err(ModelError::Protocol("model stream exceeds size limit"));
            }
            // Process incrementally, so a single large network chunk cannot allocate an unbounded line.
            for b in chunk {
                if let Some(event) = parser.push(b)? {
                    if event == b"[DONE]" {
                        return Ok(());
                    }
                    let value: Value = serde_json::from_slice(&event)
                        .map_err(|_| ModelError::Protocol("invalid model stream JSON"))?;
                    if !value.is_object() {
                        return Err(ModelError::Protocol("model stream event must be an object"));
                    }
                    tokio::select! {
                        _ = cancel.cancelled() => return Err(ModelError::Cancelled),
                        result = output.send(value) => if result.is_err() { return Err(ModelError::ConsumerClosed); },
                    }
                }
            }
        }
    }
}
fn check_status(response: &Response) -> Result<(), ModelError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(ModelError::HttpStatus(response.status()))
    }
}

#[derive(Default)]
struct SseParser {
    line: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
}
impl SseParser {
    fn push(&mut self, b: u8) -> Result<Option<Vec<u8>>, ModelError> {
        if b != b'\n' {
            if self.line.len() >= MAX_LINE {
                return Err(ModelError::Protocol("model stream line exceeds size limit"));
            }
            self.line.push(b);
            return Ok(None);
        }
        if self.line.last() == Some(&b'\r') {
            self.line.pop();
        }
        let line = std::mem::take(&mut self.line);
        // SSE is UTF-8, including ignored fields. Validate only after an entire line is assembled.
        std::str::from_utf8(&line)
            .map_err(|_| ModelError::Protocol("model stream is not UTF-8"))?;
        if line.is_empty() {
            if !self.has_data {
                return Ok(None);
            }
            self.has_data = false;
            return Ok(Some(std::mem::take(&mut self.data)));
        }
        if line[0] == b':' {
            return Ok(None);
        }
        let colon = line.iter().position(|b| *b == b':').unwrap_or(line.len());
        if &line[..colon] == b"data" {
            let mut value = if colon < line.len() {
                &line[colon + 1..]
            } else {
                &[]
            };
            if value.first() == Some(&b' ') {
                value = &value[1..];
            }
            let size = self
                .data
                .len()
                .saturating_add(value.len())
                .saturating_add(usize::from(self.has_data));
            if size > MAX_EVENT {
                return Err(ModelError::Protocol(
                    "model stream event exceeds size limit",
                ));
            }
            if self.has_data {
                self.data.push(b'\n');
            }
            self.data.extend_from_slice(value);
            self.has_data = true;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_model_choice_requires_one_valid_id() {
        assert_eq!(
            single_model_id(&serde_json::json!({"data":[{"id":"model-a"}]})).unwrap(),
            "model-a"
        );
        assert!(single_model_id(&serde_json::json!({"data":[]})).is_err());
        assert!(single_model_id(&serde_json::json!({"data":[{"id":"a"},{"id":"b"}]})).is_err());
        assert!(single_model_id(&serde_json::json!({"data":[{"id":""}]})).is_err());
    }
    #[test]
    fn parser_handles_split_utf8_crlf_and_multiline() {
        let mut p = SseParser::default();
        let input = ": ping\r\ndata: {\"text\":\r\ndata: \"é\"}\r\n\r\n";
        let mut event = None;
        for byte in input.as_bytes() {
            if let Some(v) = p.push(*byte).unwrap() {
                event = Some(v);
            }
        }
        let v: Value = serde_json::from_slice(&event.unwrap()).unwrap();
        assert_eq!(v["text"], "é");
    }
    #[test]
    fn rejects_invalid_utf8_and_oversized_line() {
        let mut p = SseParser::default();
        p.push(0xff).unwrap();
        assert!(matches!(p.push(b'\n'), Err(ModelError::Protocol(_))));
        let mut p = SseParser::default();
        for _ in 0..MAX_LINE {
            p.push(b'x').unwrap();
        }
        assert!(matches!(p.push(b'x'), Err(ModelError::Protocol(_))));
    }
    #[tokio::test]
    async fn mock_server_discovery_and_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let n = socket.read(&mut request).await.unwrap();
            assert!(std::str::from_utf8(&request[..n])
                .unwrap()
                .starts_with("GET /v1/models "));
            let body = r#"{"data":[{"id":"local-model"}]}"#;
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
            let (mut socket, _) = listener.accept().await.unwrap();
            let n = socket.read(&mut request).await.unwrap();
            assert!(std::str::from_utf8(&request[..n])
                .unwrap()
                .starts_with("POST /v1/chat/completions "));
            let body =
                "data: {\"choices\":[{\"delta\":{\"content\":\"é\"}}]}\r\n\r\ndata: [DONE]\r\n\r\n";
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            for chunk in body.as_bytes().chunks(3) {
                socket.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let client = ModelClient::new(
            &format!("http://{addr}/v1"),
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        assert_eq!(
            client.models(&cancel).await.unwrap()["data"][0]["id"],
            "local-model"
        );
        let (tx, mut rx) = mpsc::channel(4);
        client
            .stream_chat(
                serde_json::json!({"model":"local-model","messages":[]}),
                tx,
                &cancel,
            )
            .await
            .unwrap();
        assert_eq!(
            rx.recv().await.unwrap()["choices"][0]["delta"]["content"],
            "é"
        );
        assert!(rx.recv().await.is_none());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn cancellation_interrupts_a_stalled_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let client = ModelClient::new(
            &format!("http://{addr}/v1"),
            Duration::from_secs(2),
            Duration::from_secs(10),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let task = tokio::spawn(async move { client.models(&c).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            Err(ModelError::Cancelled)
        ));
        server.abort();
    }
    #[test]
    fn rejects_unsafe_or_invalid_configuration() {
        assert!(ModelClient::new(
            "http://user:password@localhost/v1",
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(ModelClient::new(
            "file:///tmp",
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(ModelClient::new(
            "http://localhost/v1?x=y",
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err());
    }
}
