pub mod starknet_app;

use std::{
    borrow::Cow,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use reqwest::{Client, ClientBuilder};
use serde::{Serialize, ser::SerializeSeq};
use serde_json::{Value, json};

#[derive(Debug)]
pub struct SpeculosClient {
    process: Child,
    port: u16,
    client: Client,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutomationRule<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regexp: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<u32>,
    pub conditions: &'a [AutomationCondition<'a>],
    pub actions: &'a [AutomationAction<'a>],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomationAction<'a> {
    Button { button: Button, pressed: bool },
    Setbool { varname: Cow<'a, str>, value: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomationCondition<'a> {
    pub varname: Cow<'a, str>,
    pub value: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
}

#[derive(Debug)]
pub enum SpeculosError {
    IoError(std::io::Error),
    ReqwestError(reqwest::Error),
    Timeout,
    ProcessExited(Option<i32>),
    InvalidResponse(&'static str),
    PortInUse(u16),
}

#[derive(Serialize)]
struct PostAutomationRequest<'a> {
    version: u32,
    rules: &'a [AutomationRule<'a>],
}

struct StderrWatcher {
    ready_rx: std::sync::mpsc::Receiver<()>,
    handle: JoinHandle<()>,
}

impl StderrWatcher {
    fn try_recv_ready(&self) -> bool {
        self.ready_rx.try_recv().is_ok()
    }
}

impl SpeculosClient {
    pub fn new<P: AsRef<Path>>(port: u16, app: P) -> Result<Self, SpeculosError> {
        Self::new_with_timeout(port, app, Duration::from_secs(10))
    }

    pub fn new_with_timeout<P: AsRef<Path>>(
        port: u16,
        app: P,
        timeout: Duration,
    ) -> Result<Self, SpeculosError> {
        ensure_port_available(port)?;

        let client = ClientBuilder::new().build()?;

        let mut process = Command::new("speculos")
            .args([
                "--api-port",
                &port.to_string(),
                "--apdu-port",
                "0",
                "-m",
                "nanox",
                "--display",
                "headless",
                &app.as_ref().display().to_string(),
            ])
            .stderr(Stdio::piped())
            .spawn()?;

        let deadline = Instant::now() + timeout;
        let addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("valid localhost address");
        let mut stderr_watcher = spawn_stderr_watcher(process.stderr.take());
        let mut app_ready = stderr_watcher.is_none();

        loop {
            if Instant::now() >= deadline {
                join_stderr_watcher(stderr_watcher.take(), &mut process);
                return Err(SpeculosError::Timeout);
            }
            if let Ok(Some(status)) = process.try_wait() {
                join_stderr_watcher(stderr_watcher.take(), &mut process);
                return Err(SpeculosError::ProcessExited(status.code()));
            }

            if let Some(watcher) = &stderr_watcher
                && !app_ready
                && watcher.try_recv_ready()
            {
                app_ready = true;
            }

            if !app_ready {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            let io_timeout = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(500));
            if events_api_ready(&addr, port, io_timeout) {
                stderr_watcher.take();
                return Ok(Self {
                    process,
                    port,
                    client,
                });
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub async fn wait_for_events(&self, timeout: Duration) -> Result<(), SpeculosError> {
        let deadline = Instant::now() + timeout;

        loop {
            if Instant::now() >= deadline {
                return Err(SpeculosError::Timeout);
            }

            let response = self
                .client
                .get(format!("http://127.0.0.1:{}/events", self.port))
                .send()
                .await?;

            if response.status().is_success() {
                let body: Value = response.json().await?;
                if events_value_ready(&body) {
                    return Ok(());
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn apdu(&self, data: &[u8]) -> Result<Vec<u8>, SpeculosError> {
        let response = self
            .client
            .post(format!("http://127.0.0.1:{}/apdu", self.port))
            .json(&json!({ "data": hex::encode(data) }))
            .send()
            .await?;
        let body: Value = response.error_for_status()?.json().await?;
        let hex_str = body["data"].as_str().ok_or(SpeculosError::InvalidResponse(
            "missing data field in APDU response",
        ))?;
        hex::decode(hex_str)
            .map_err(|_| SpeculosError::InvalidResponse("invalid hex in APDU response"))
    }

    pub async fn automation(&self, rules: &[AutomationRule<'_>]) -> Result<(), SpeculosError> {
        let response = self
            .client
            .post(format!("http://127.0.0.1:{}/automation", self.port))
            .json(&PostAutomationRequest { version: 1, rules })
            .send()
            .await?;
        response.error_for_status()?;
        Ok(())
    }

    pub async fn click_button(&self, button: Button) -> Result<(), SpeculosError> {
        #[derive(Serialize)]
        struct ButtonRequest {
            action: &'static str,
        }
        let name = match button {
            Button::Left => "left",
            Button::Right => "right",
        };
        let response = self
            .client
            .post(format!("http://127.0.0.1:{}/button/{name}", self.port))
            .json(&ButtonRequest {
                action: "press-and-release",
            })
            .send()
            .await?;
        response.error_for_status()?;
        Ok(())
    }
}

impl Drop for SpeculosClient {
    fn drop(&mut self) {
        kill_and_wait(&mut self.process);
    }
}

impl Serialize for AutomationCondition<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.varname)?;
        seq.serialize_element(&self.value)?;
        seq.end()
    }
}

impl Serialize for AutomationAction<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Button { button, pressed } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("button")?;
                seq.serialize_element(&match button {
                    Button::Left => 1,
                    Button::Right => 2,
                })?;
                seq.serialize_element(pressed)?;
                seq.end()
            }
            Self::Setbool { varname, value } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("setbool")?;
                seq.serialize_element(varname)?;
                seq.serialize_element(value)?;
                seq.end()
            }
        }
    }
}

impl From<std::io::Error> for SpeculosError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<reqwest::Error> for SpeculosError {
    fn from(value: reqwest::Error) -> Self {
        Self::ReqwestError(value)
    }
}

impl std::fmt::Display for SpeculosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "{e}"),
            Self::ReqwestError(e) => write!(f, "{e}"),
            Self::Timeout => write!(f, "speculos startup timed out"),
            Self::ProcessExited(code) => match code {
                Some(code) => write!(f, "speculos exited with status {code}"),
                None => write!(f, "speculos exited"),
            },
            Self::InvalidResponse(msg) => write!(f, "invalid speculos response: {msg}"),
            Self::PortInUse(port) => write!(f, "speculos API port {port} is already in use"),
        }
    }
}

fn ensure_port_available(port: u16) -> Result<(), SpeculosError> {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            Err(SpeculosError::PortInUse(port))
        }
        Err(error) => Err(SpeculosError::IoError(error)),
    }
}

fn spawn_stderr_watcher(stderr: Option<impl Read + Send + 'static>) -> Option<StderrWatcher> {
    let stderr = stderr?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if is_app_ready_log_line(&line) {
                let _ = ready_tx.send(());
            }
        }
    });
    Some(StderrWatcher { ready_rx, handle })
}

fn join_stderr_watcher(watcher: Option<StderrWatcher>, process: &mut Child) {
    kill_and_wait(process);
    if let Some(watcher) = watcher {
        let _ = watcher.handle.join();
    }
}

fn is_app_ready_log_line(line: &str) -> bool {
    line.contains("launcher: using default app name & version")
        || line.contains("[*] Env app version:")
}

fn events_api_ready(addr: &SocketAddr, port: u16, timeout: Duration) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(addr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let request =
        format!("GET /events HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }

    let Some(body) = http_response_body(&response) else {
        return false;
    };

    http_response_ok(&response)
        && serde_json::from_str::<Value>(body.trim())
            .ok()
            .is_some_and(|value| events_value_ready(&value))
}

fn http_response_ok(response: &str) -> bool {
    response
        .lines()
        .next()
        .is_some_and(|status_line| status_line.contains("200"))
}

fn http_response_body(response: &str) -> Option<&str> {
    response
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| response.split("\n\n").nth(1))
}

fn events_value_ready(value: &Value) -> bool {
    if let Some(events) = value.get("events").and_then(Value::as_array) {
        return events.iter().any(|event| event.get("text").is_some());
    }

    match value {
        Value::Array(events) => events.iter().any(|event| event.get("text").is_some()),
        Value::Object(event) => event.contains_key("text"),
        _ => false,
    }
}

fn kill_and_wait(process: &mut Child) {
    let _ = process.kill();
    let _ = process.wait();
}

impl std::error::Error for SpeculosError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn events_value_ready_accepts_object_and_array_payloads() {
        assert!(events_value_ready(&json!({ "text": "Approve" })));
        assert!(events_value_ready(&json!([{ "text": "Approve" }])));
        assert!(events_value_ready(
            &json!({ "events": [{ "text": "Approve" }] })
        ));
        assert!(!events_value_ready(&json!({ "events": [] })));
        assert!(!events_value_ready(&json!({ "event": "screen" })));
        assert!(!events_value_ready(&json!("ready")));
    }

    #[test]
    fn http_response_body_splits_headers() {
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"text\":\"x\"}";
        assert_eq!(http_response_body(response), Some("{\"text\":\"x\"}"));
    }

    #[test]
    #[ignore = "requires speculos"]
    fn startup_fails_fast_with_short_deadline() {
        let err = SpeculosClient::new_with_timeout(59999, "/dev/null", Duration::from_millis(100));
        assert!(matches!(
            err,
            Err(SpeculosError::Timeout | SpeculosError::ProcessExited(_))
        ));
    }
}
