//! Translation of OpenAI-compatible SSE chat streams into AG-UI events.
//! This module does not authorize requests, execute tools, or persist events;
//! callers must do those jobs before exposing it as a conversation run.
use crate::model::{ModelClient, ModelError};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, fmt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Maximum number of tool calls accepted in a single model turn.
pub const MAX_TOOL_CALLS_PER_TURN: usize = 16;
/// Maximum accumulated argument bytes accepted for a single tool call.
pub const MAX_TOOL_ARGS_BYTES: usize = 64 * 1024;
const MAX_ASSISTANT_TEXT_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum RunError {
    Model(ModelError),
    Upstream(String),
    Cancelled,
    ConsumerClosed,
    Protocol(&'static str),
}

pub(crate) fn is_memory_or_context_error_msg(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("bad_alloc")
        || lower.contains("internal memory")
        || lower.contains("context size")
        || lower.contains("out of memory")
        || lower.contains("ran out of memory")
}

impl RunError {
    pub fn is_oom_or_context_error(&self) -> bool {
        match self {
            Self::Upstream(msg) => is_memory_or_context_error_msg(msg),
            _ => false,
        }
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(e) => write!(f, "{e}"),
            Self::Upstream(msg) => {
                if is_memory_or_context_error_msg(msg) {
                    if msg.starts_with("PS5LM ran out of memory") {
                        f.write_str(msg)
                    } else {
                        write!(
                            f,
                            "PS5LM ran out of memory (std::bad_alloc): {msg}. Load a smaller model (e.g. 9B/2B) or start a shorter chat."
                        )
                    }
                } else {
                    f.write_str(msg)
                }
            }
            Self::Cancelled => f.write_str("run cancelled"),
            Self::ConsumerClosed => f.write_str("run consumer closed"),
            Self::Protocol(e) => f.write_str(e),
        }
    }
}

/// A completed tool call accumulated from fragmented `delta.tool_calls` chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedToolCall {
    pub id: String,
    pub name: String,
    pub arguments_json: String,
}

/// Summary of one streamed model turn after all open AG-UI messages and tool calls close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnResult {
    pub assistant_text: String,
    pub tool_calls: Vec<CollectedToolCall>,
    pub finish_reason: String,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 200 && !id.chars().any(char::is_control)
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && !name.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn extract_choice_delta<'a>(
    chunk: &'a Value,
    finished: bool,
) -> Result<Option<(&'a Value, &'a Map<String, Value>)>, RunError> {
    if finished {
        return Err(RunError::Protocol("data after model finish"));
    }
    if let Some(err_val) = chunk.get("error") {
        let msg = err_val
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| err_val.as_str())
            .unwrap_or("model reported an error")
            .trim()
            .to_owned();
        return Err(RunError::Upstream(msg));
    }
    let choices = chunk
        .get("choices")
        .and_then(Value::as_array)
        .ok_or(RunError::Protocol("missing choices"))?;
    if choices.is_empty() {
        return Ok(None);
    }
    if choices.len() != 1
        || choices[0]
            .get("index")
            .and_then(Value::as_u64)
            .is_some_and(|i| i != 0)
    {
        return Err(RunError::Protocol("multiple model choices are unsupported"));
    }
    let choice = &choices[0];
    let delta = choice
        .get("delta")
        .and_then(Value::as_object)
        .ok_or(RunError::Protocol("missing delta"))?;
    Ok(Some((choice, delta)))
}

fn parse_text_delta(delta: &Map<String, Value>) -> Result<Option<&str>, RunError> {
    match delta.get("content") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        _ => Err(RunError::Protocol("invalid model content")),
    }
}

/// A single-choice text response. Tool calls are rejected until the policy
/// gateway exists; never execute or silently discard a model-requested tool.
#[derive(Default)]
struct TextStream {
    finished: bool,
}
impl TextStream {
    fn chunk(&mut self, chunk: &Value) -> Result<Option<String>, RunError> {
        let Some((choice, delta)) = extract_choice_delta(chunk, self.finished)? else {
            return Ok(None);
        };
        if delta.get("tool_calls").is_some_and(|v| !v.is_null())
            || delta.get("function_call").is_some_and(|v| !v.is_null())
        {
            return Err(RunError::Protocol("model tool calls are not available"));
        }
        let content = parse_text_delta(delta)?.map(str::to_owned);
        match choice.get("finish_reason") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s == "stop" => self.finished = true,
            Some(Value::String(s)) if s == "length" => {
                return Err(RunError::Protocol("model output reached its limit"))
            }
            _ => return Err(RunError::Protocol("unsupported model finish reason")),
        };
        Ok(content)
    }
}

#[derive(Default)]
struct ToolCallSlot {
    id: String,
    name: String,
    arguments_json: String,
    started: bool,
}

/// Stateful accumulator for one OpenAI-compatible turn supporting both
/// assistant text deltas and fragmented `delta.tool_calls` arrays.
#[derive(Default)]
struct TurnStream {
    finished: bool,
    finish_reason: Option<String>,
    assistant_text: String,
    text_started: bool,
    tool_calls: BTreeMap<usize, ToolCallSlot>,
}

impl TurnStream {
    fn chunk(&mut self, chunk: &Value, message_id: &str) -> Result<Vec<Value>, RunError> {
        let Some((choice, delta)) = extract_choice_delta(chunk, self.finished)? else {
            return Ok(Vec::new());
        };
        if delta.get("function_call").is_some_and(|v| !v.is_null()) {
            return Err(RunError::Protocol("legacy function_call is unsupported"));
        }

        let mut events = Vec::new();
        if let Some(text) = parse_text_delta(delta)? {
            if self.assistant_text.len().saturating_add(text.len()) > MAX_ASSISTANT_TEXT_BYTES {
                return Err(RunError::Protocol("assistant text exceeded size limit"));
            }
            if !self.text_started {
                self.text_started = true;
                events.push(json!({
                    "type": "TEXT_MESSAGE_START",
                    "messageId": message_id,
                    "role": "assistant",
                }));
            }
            self.assistant_text.push_str(text);
            events.push(json!({
                "type": "TEXT_MESSAGE_CONTENT",
                "messageId": message_id,
                "delta": text,
            }));
        }

        match delta.get("tool_calls") {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    self.apply_tool_delta(item, message_id, &mut events)?;
                }
            }
            _ => return Err(RunError::Protocol("invalid tool_calls")),
        }

        match choice.get("finish_reason") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s == "stop" || s == "tool_calls" => {
                if s == "tool_calls" && self.tool_calls.is_empty() {
                    return Err(RunError::Protocol(
                        "tool_calls finish reason without tool calls",
                    ));
                }
                self.finished = true;
                self.finish_reason = Some(s.clone());
            }
            Some(Value::String(s)) if s == "length" => {
                return Err(RunError::Protocol("model output reached its limit"));
            }
            _ => return Err(RunError::Protocol("unsupported model finish reason")),
        }

        Ok(events)
    }

    fn apply_tool_delta(
        &mut self,
        item: &Value,
        message_id: &str,
        events: &mut Vec<Value>,
    ) -> Result<(), RunError> {
        let tc = item
            .as_object()
            .ok_or(RunError::Protocol("invalid tool call delta"))?;
        let index = tc
            .get("index")
            .and_then(Value::as_u64)
            .ok_or(RunError::Protocol("missing tool call index"))?;
        if index >= MAX_TOOL_CALLS_PER_TURN as u64 {
            return Err(RunError::Protocol("too many tool calls in turn"));
        }
        match tc.get("type") {
            None | Some(Value::Null) => {}
            Some(Value::String(kind)) if kind == "function" => {}
            _ => return Err(RunError::Protocol("unsupported tool call type")),
        }

        let slot = self.tool_calls.entry(index as usize).or_default();
        if let Some(id_val) = tc.get("id").filter(|v| !v.is_null()) {
            let id = id_val
                .as_str()
                .filter(|s| valid_id(s))
                .ok_or(RunError::Protocol("invalid tool call id"))?;
            if !slot.id.is_empty() && slot.id != id {
                return Err(RunError::Protocol("conflicting tool call id"));
            }
            if slot.id.is_empty() {
                slot.id = id.to_owned();
            }
        }

        let mut new_args: Option<&str> = None;
        if let Some(func_val) = tc.get("function").filter(|v| !v.is_null()) {
            let func = func_val
                .as_object()
                .ok_or(RunError::Protocol("invalid tool call function"))?;
            if let Some(name_val) = func.get("name").filter(|v| !v.is_null()) {
                let name = name_val
                    .as_str()
                    .filter(|s| valid_tool_name(s))
                    .ok_or(RunError::Protocol("invalid tool name"))?;
                if !slot.name.is_empty() && slot.name != name {
                    return Err(RunError::Protocol("conflicting tool name"));
                }
                if slot.name.is_empty() {
                    slot.name = name.to_owned();
                }
            }
            if let Some(args_val) = func.get("arguments").filter(|v| !v.is_null()) {
                let args = args_val
                    .as_str()
                    .ok_or(RunError::Protocol("invalid tool call arguments"))?;
                if slot.arguments_json.len().saturating_add(args.len()) > MAX_TOOL_ARGS_BYTES {
                    return Err(RunError::Protocol(
                        "tool call arguments exceed size limit",
                    ));
                }
                slot.arguments_json.push_str(args);
                if !args.is_empty() {
                    new_args = Some(args);
                }
            }
        }

        // Emit TOOL_CALL_START only once both id and name are known so every
        // TOOL_CALL_ARGS delta has a valid preceding TOOL_CALL_START.
        if !slot.started && !slot.id.is_empty() && !slot.name.is_empty() {
            slot.started = true;
            events.push(json!({
                "type": "TOOL_CALL_START",
                "toolCallId": slot.id,
                "toolCallName": slot.name,
                "parentMessageId": message_id,
            }));
            if !slot.arguments_json.is_empty() {
                events.push(json!({
                    "type": "TOOL_CALL_ARGS",
                    "toolCallId": slot.id,
                    "delta": slot.arguments_json,
                }));
            }
        } else if slot.started {
            if let Some(args) = new_args {
                events.push(json!({
                    "type": "TOOL_CALL_ARGS",
                    "toolCallId": slot.id,
                    "delta": args,
                }));
            }
        }
        Ok(())
    }

    fn finish(
        self,
        thread_id: &str,
        run_id: &str,
        message_id: &str,
        emit_run_finished: bool,
    ) -> Result<(Vec<Value>, TurnResult), RunError> {
        let Some(finish_reason) = self.finish_reason else {
            return Err(RunError::Protocol(
                "model stream ended without a finish reason",
            ));
        };
        let mut events = Vec::new();
        if self.text_started {
            events.push(json!({
                "type": "TEXT_MESSAGE_END",
                "messageId": message_id,
            }));
        }
        let mut collected = Vec::with_capacity(self.tool_calls.len());
        for (_, slot) in self.tool_calls {
            if !slot.started || slot.id.is_empty() || slot.name.is_empty() {
                return Err(RunError::Protocol("incomplete tool call in model stream"));
            }
            events.push(json!({
                "type": "TOOL_CALL_END",
                "toolCallId": slot.id,
            }));
            collected.push(CollectedToolCall {
                id: slot.id,
                name: slot.name,
                arguments_json: slot.arguments_json,
            });
        }
        if emit_run_finished {
            events.push(json!({
                "type": "RUN_FINISHED",
                "threadId": thread_id,
                "runId": run_id,
            }));
        }
        Ok((
            events,
            TurnResult {
                assistant_text: self.assistant_text,
                tool_calls: collected,
                finish_reason,
            },
        ))
    }
}

/// Build an AG-UI `TOOL_CALL_RESULT` event for a completed tool execution.
pub fn ag_ui_tool_result(
    message_id: &str,
    tool_call_id: &str,
    content_json: &str,
) -> Result<Value, RunError> {
    if !valid_id(message_id) || !valid_id(tool_call_id) {
        return Err(RunError::Protocol("invalid tool result identifiers"));
    }
    Ok(json!({
        "type": "TOOL_CALL_RESULT",
        "messageId": message_id,
        "toolCallId": tool_call_id,
        "role": "tool",
        "content": content_json,
    }))
}

/// Build an AG-UI `RUN_FINISHED` interrupt event pausing for HITL tool approval.
/// `openbot_waiting` must be a non-null JSON object attached under `metadata.openbotWaiting`.
pub fn ag_ui_interrupt_finished(
    thread_id: &str,
    run_id: &str,
    interrupt_id: &str,
    tool_call_id: &str,
    message: Option<&str>,
    openbot_waiting: Value,
) -> Result<Value, RunError> {
    if ![thread_id, run_id, interrupt_id, tool_call_id]
        .iter()
        .all(|s| valid_id(s))
    {
        return Err(RunError::Protocol("invalid interrupt identifiers"));
    }
    if !openbot_waiting.is_object() {
        return Err(RunError::Protocol(
            "openbotWaiting metadata must be a non-null object",
        ));
    }
    let msg = message
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or("Approval required");
    Ok(json!({
        "type": "RUN_FINISHED",
        "threadId": thread_id,
        "runId": run_id,
        "outcome": {
            "type": "interrupt",
            "interrupts": [
                {
                    "id": interrupt_id,
                    "toolCallId": tool_call_id,
                    "reason": "tool_call",
                    "message": msg,
                    "metadata": {
                        "openbotWaiting": openbot_waiting,
                    }
                }
            ]
        }
    }))
}

async fn emit(
    output: &mpsc::Sender<Value>,
    cancel: &CancellationToken,
    event: Value,
) -> Result<(), RunError> {
    tokio::select! {_ = cancel.cancelled()=>Err(RunError::Cancelled),r=output.send(event)=>r.map_err(|_|RunError::ConsumerClosed)}
}

/// Emits start, text and finish events to a bounded consumer. The caller must
/// persist them in order and emit RUN_ERROR if this function returns an error.
/// No automatic retries are attempted. Dropping the consumer cancels the HTTP request.
pub async fn stream_text(
    client: ModelClient,
    request: Value,
    thread_id: &str,
    run_id: &str,
    message_id: &str,
    output: mpsc::Sender<Value>,
    cancel: CancellationToken,
) -> Result<(), RunError> {
    if ![thread_id, run_id, message_id].iter().all(|s| valid_id(s)) {
        return Err(RunError::Protocol("invalid run identifiers"));
    }
    emit(
        &output,
        &cancel,
        json!({"type":"RUN_STARTED","threadId":thread_id,"runId":run_id}),
    )
    .await?;
    emit(
        &output,
        &cancel,
        json!({"type":"TEXT_MESSAGE_START","messageId":message_id,"role":"assistant"}),
    )
    .await?;
    let (tx, mut rx) = mpsc::channel(16);
    let task_cancel = cancel.child_token();
    let worker_cancel = task_cancel.clone();
    let worker = tokio::spawn(async move { client.stream_chat(request, tx, &worker_cancel).await });
    let mut state = TextStream::default();
    let result=async {
        while let Some(chunk)=tokio::select!{_ = cancel.cancelled()=>return Err(RunError::Cancelled),_ = output.closed()=>return Err(RunError::ConsumerClosed),v=rx.recv()=>v} {
            if let Some(content)=state.chunk(&chunk)? { emit(&output,&cancel,json!({"type":"TEXT_MESSAGE_CONTENT","messageId":message_id,"delta":content})).await?; }
        }
        match worker.await {Ok(Ok(()))=>{},Ok(Err(e))=>return Err(RunError::Model(e)),Err(_)=>return Err(RunError::Protocol("model worker failed"))};
        if !state.finished{return Err(RunError::Protocol("model stream ended without a finish reason"));}
        emit(&output,&cancel,json!({"type":"TEXT_MESSAGE_END","messageId":message_id})).await?;
        emit(&output,&cancel,json!({"type":"RUN_FINISHED","threadId":thread_id,"runId":run_id})).await
    }.await;
    task_cancel.cancel();
    result
}

/// Streams a single OpenAI-compatible turn, emitting `TEXT_MESSAGE_*` (only when
/// non-empty assistant text appears) and `TOOL_CALL_*` AG-UI events, closing all
/// open message/tool scopes before optionally emitting `RUN_FINISHED`.
pub async fn stream_turn(
    client: ModelClient,
    request: Value,
    thread_id: &str,
    run_id: &str,
    message_id: &str,
    emit_run_finished: bool,
    output: mpsc::Sender<Value>,
    cancel: CancellationToken,
) -> Result<TurnResult, RunError> {
    if ![thread_id, run_id, message_id].iter().all(|s| valid_id(s)) {
        return Err(RunError::Protocol("invalid run identifiers"));
    }
    let (tx, mut rx) = mpsc::channel(16);
    let task_cancel = cancel.child_token();
    let worker_cancel = task_cancel.clone();
    let worker = tokio::spawn(async move { client.stream_chat(request, tx, &worker_cancel).await });
    let mut state = TurnStream::default();
    let result = async {
        while let Some(chunk) = tokio::select! {
            _ = cancel.cancelled() => return Err(RunError::Cancelled),
            _ = output.closed() => return Err(RunError::ConsumerClosed),
            v = rx.recv() => v,
        } {
            for event in state.chunk(&chunk, message_id)? {
                emit(&output, &cancel, event).await?;
            }
        }
        match worker.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(RunError::Model(e)),
            Err(_) => return Err(RunError::Protocol("model worker failed")),
        }
        let (closing_events, turn_result) =
            state.finish(thread_id, run_id, message_id, emit_run_finished)?;
        for event in closing_events {
            emit(&output, &cancel, event).await?;
        }
        Ok(turn_result)
    }
    .await;
    task_cancel.cancel();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve_sse_once(body: &'static str) -> (ModelClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let client = ModelClient::new(
            &format!("http://{addr}/v1"),
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .unwrap();
        (client, mock)
    }

    #[tokio::test]
    async fn mock_model_stream_emits_ordered_ag_ui_events() {
        let (client, mock) = serve_sse_once(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
        )
        .await;
        let (tx, mut rx) = mpsc::channel(16);
        stream_text(
            client,
            json!({"model":"mock","messages":[]}),
            "thread",
            "run",
            "message",
            tx,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }
        assert_eq!(
            events
                .iter()
                .map(|e| e["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "RUN_STARTED",
                "TEXT_MESSAGE_START",
                "TEXT_MESSAGE_CONTENT",
                "TEXT_MESSAGE_END",
                "RUN_FINISHED"
            ]
        );
        assert_eq!(events[2]["delta"], "hello");
        mock.await.unwrap();
    }

    #[test]
    fn text_stream_checks_finish_and_rejects_tools() {
        let mut state = TextStream::default();
        assert_eq!(
            state
                .chunk(&json!({"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}))
                .unwrap()
                .as_deref(),
            Some("hello")
        );
        assert!(state
            .chunk(&json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}))
            .is_ok());
        assert!(state.finished);
        assert!(state.chunk(&json!({"choices":[]})).is_err());
        let mut state = TextStream::default();
        assert!(state
            .chunk(&json!({"choices":[{"delta":{"tool_calls":[{"id":"x"}]}}]}))
            .is_err());
        assert!(TextStream::default()
            .chunk(&json!({"choices":[{"delta":{},"finish_reason":"length"}]}))
            .is_err());
    }

    #[tokio::test]
    async fn stream_turn_accumulates_fragmented_parallel_tool_calls_and_closes_all() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_b\",\"type\":\"function\",\"function\":{\"name\":\"get_time\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"Vienna\\\"}\"}},{\"index\":1,\"function\":{\"arguments\":\"{\\\"tz\\\":\\\"UTC\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n"
        );
        let (client, mock) = serve_sse_once(sse).await;
        let (tx, mut rx) = mpsc::channel(32);
        let turn = stream_turn(
            client,
            json!({"model":"mock","messages":[]}),
            "thread-1",
            "run-1",
            "msg-1",
            false,
            tx,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }
        mock.await.unwrap();

        assert_eq!(turn.assistant_text, "");
        assert_eq!(turn.finish_reason, "tool_calls");
        assert_eq!(
            turn.tool_calls,
            vec![
                CollectedToolCall {
                    id: "call_a".to_owned(),
                    name: "get_weather".to_owned(),
                    arguments_json: "{\"city\":\"Vienna\"}".to_owned(),
                },
                CollectedToolCall {
                    id: "call_b".to_owned(),
                    name: "get_time".to_owned(),
                    arguments_json: "{\"tz\":\"UTC\"}".to_owned(),
                },
            ]
        );
        assert_eq!(
            events
                .iter()
                .map(|e| (
                    e["type"].as_str().unwrap(),
                    e["toolCallId"].as_str().unwrap_or("")
                ))
                .collect::<Vec<_>>(),
            vec![
                ("TOOL_CALL_START", "call_a"),
                ("TOOL_CALL_ARGS", "call_a"),
                ("TOOL_CALL_START", "call_b"),
                ("TOOL_CALL_ARGS", "call_a"),
                ("TOOL_CALL_ARGS", "call_b"),
                ("TOOL_CALL_END", "call_a"),
                ("TOOL_CALL_END", "call_b"),
            ]
        );
        assert_eq!(events[0]["toolCallName"], "get_weather");
        assert_eq!(events[0]["parentMessageId"], "msg-1");
        assert_eq!(events[2]["toolCallName"], "get_time");
        assert_eq!(events[2]["parentMessageId"], "msg-1");
        assert!(!events
            .iter()
            .any(|e| e["type"].as_str().unwrap().starts_with("TEXT_MESSAGE_")));
        assert!(!events.iter().any(|e| e["type"] == "RUN_FINISHED"));
    }

    #[tokio::test]
    async fn stream_turn_emits_text_and_run_finished_on_stop() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi \"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"there\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n"
        );
        let (client, mock) = serve_sse_once(sse).await;
        let (tx, mut rx) = mpsc::channel(16);
        let turn = stream_turn(
            client,
            json!({"model":"mock","messages":[]}),
            "thread-1",
            "run-1",
            "msg-1",
            true,
            tx,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }
        mock.await.unwrap();

        assert_eq!(turn.assistant_text, "Hi there");
        assert!(turn.tool_calls.is_empty());
        assert_eq!(turn.finish_reason, "stop");
        assert_eq!(
            events
                .iter()
                .map(|e| e["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "TEXT_MESSAGE_START",
                "TEXT_MESSAGE_CONTENT",
                "TEXT_MESSAGE_CONTENT",
                "TEXT_MESSAGE_END",
                "RUN_FINISHED",
            ]
        );
        assert_eq!(events[4]["threadId"], "thread-1");
        assert_eq!(events[4]["runId"], "run-1");
    }

    #[test]
    fn turn_stream_supports_text_plus_tool_calls_and_fragmented_id_name() {
        let mut state = TurnStream::default();
        let mut emitted = Vec::new();
        emitted.extend(
            state
                .chunk(
                    &json!({"choices":[{"index":0,"delta":{"content":"Checking..."},"finish_reason":null}]}),
                    "msg-1",
                )
                .unwrap(),
        );
        // Split id, name, and arguments across chunks.
        emitted.extend(
            state
                .chunk(
                    &json!({"choices":[{"index":0,"delta":{"content":null,"tool_calls":[{"index":0,"id":"call_1","function":{"arguments":"{\"k\":"}}]},"finish_reason":null}]}),
                    "msg-1",
                )
                .unwrap(),
        );
        emitted.extend(
            state
                .chunk(
                    &json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"lookup","arguments":"1}"}}]},"finish_reason":"tool_calls"}]}),
                    "msg-1",
                )
                .unwrap(),
        );
        let (closing, turn) = state.finish("t1", "r1", "msg-1", false).unwrap();
        emitted.extend(closing);

        assert_eq!(turn.assistant_text, "Checking...");
        assert_eq!(
            turn.tool_calls,
            vec![CollectedToolCall {
                id: "call_1".to_owned(),
                name: "lookup".to_owned(),
                arguments_json: "{\"k\":1}".to_owned(),
            }]
        );
        assert_eq!(
            emitted
                .iter()
                .map(|e| e["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "TEXT_MESSAGE_START",
                "TEXT_MESSAGE_CONTENT",
                "TOOL_CALL_START",
                "TOOL_CALL_ARGS",
                "TEXT_MESSAGE_END",
                "TOOL_CALL_END",
            ]
        );
        assert_eq!(emitted[3]["delta"], "{\"k\":1}");
    }

    #[test]
    fn turn_stream_rejects_invalid_tool_names_and_bounds() {
        // Empty tool name
        let mut state = TurnStream::default();
        assert!(state
            .chunk(
                &json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":""}}]}}]}),
                "m1",
            )
            .is_err());

        // Whitespace in tool name
        let mut state = TurnStream::default();
        assert!(state
            .chunk(
                &json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"bad tool"}}]}}]}),
                "m1",
            )
            .is_err());

        // Exceeds max tool calls per turn (index 16 >= 16)
        let mut state = TurnStream::default();
        assert!(state
            .chunk(
                &json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":16,"id":"c16","function":{"name":"ok"}}]}}]}),
                "m1",
            )
            .is_err());

        // Exceeds max argument bytes (64 KiB + 1)
        let mut state = TurnStream::default();
        let exact_max = "a".repeat(MAX_TOOL_ARGS_BYTES);
        assert!(state
            .chunk(
                &json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c0","function":{"name":"ok","arguments":exact_max}}]}}]}),
                "m1",
            )
            .is_ok());
        assert!(state
            .chunk(
                &json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"b"}}]}}]}),
                "m1",
            )
            .is_err());

        // Rejects length, unknown finish reason, and tool_calls finish with zero tools
        assert!(TurnStream::default()
            .chunk(
                &json!({"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}),
                "m1",
            )
            .is_err());
        assert!(TurnStream::default()
            .chunk(
                &json!({"choices":[{"index":0,"delta":{},"finish_reason":"content_filter"}]}),
                "m1",
            )
            .is_err());
        assert!(TurnStream::default()
            .chunk(
                &json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
                "m1",
            )
            .is_err());
    }

    #[test]
    fn ag_ui_tool_result_and_interrupt_finished_payloads_match_contract() {
        let tool_res = ag_ui_tool_result("res-1", "call-1", "{\"ok\":true}").unwrap();
        assert_eq!(
            tool_res,
            json!({
                "type": "TOOL_CALL_RESULT",
                "messageId": "res-1",
                "toolCallId": "call-1",
                "role": "tool",
                "content": "{\"ok\":true}",
            })
        );

        let interrupt = ag_ui_interrupt_finished(
            "thread-1",
            "run-1",
            "int-1",
            "call-1",
            None,
            json!({"approvalId": "apr-1", "tool": "fs.write"}),
        )
        .unwrap();
        assert_eq!(interrupt["type"], "RUN_FINISHED");
        assert_eq!(interrupt["threadId"], "thread-1");
        assert_eq!(interrupt["runId"], "run-1");
        assert_eq!(interrupt["outcome"]["type"], "interrupt");
        let item = &interrupt["outcome"]["interrupts"][0];
        assert_eq!(item["id"], "int-1");
        assert_eq!(item["toolCallId"], "call-1");
        assert_eq!(item["reason"], "tool_call");
        assert_eq!(item["message"], "Approval required");
        assert!(item["metadata"]["openbotWaiting"].is_object());
        assert_eq!(item["metadata"]["openbotWaiting"]["approvalId"], "apr-1");

        // Rejects null or non-object openbotWaiting
        assert!(
            ag_ui_interrupt_finished("t", "r", "i", "c", None, Value::Null).is_err()
        );
        assert!(
            ag_ui_interrupt_finished("t", "r", "i", "c", None, json!("invalid")).is_err()
        );
        assert!(ag_ui_tool_result("", "c", "{}").is_err());
    }

    #[test]
    fn oom_and_context_errors_are_detected_and_formatted_clearly() {
        for raw in [
            "decode() failed std::bad_alloc",
            "Internal Memory allocation failed",
            "Prompt exceeds context size limit",
        ] {
            let err = RunError::Upstream(raw.to_owned());
            assert!(err.is_oom_or_context_error(), "expected OOM detection for {raw}");
            let rendered = err.to_string();
            assert!(
                rendered.starts_with("PS5LM ran out of memory (std::bad_alloc)"),
                "unexpected Display for {raw}: {rendered}"
            );
        }
        let normal = RunError::Upstream("rate limit reached".to_owned());
        assert!(!normal.is_oom_or_context_error());
        assert_eq!(normal.to_string(), "rate limit reached");
    }
}
