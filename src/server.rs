use std::{
    collections::HashMap,
    env,
    fs,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    sync::{mpsc, oneshot, Mutex},
    time::interval,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        http::{self, StatusCode},
        Message,
    },
    WebSocketStream,
};

pub const DEFAULT_OPERATOR_SOCKET: &str = "/tmp/bepr.sock";
pub const DEFAULT_SERVER_CONFIG: &str = "/etc/bepr/server.conf";
pub const DEFAULT_BIND: &str = "127.0.0.1:25223";
const MAX_PENDING_OUTPUT: usize = 64 * 1024;
const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const HEARTBEAT_TIMEOUT_MS: u64 = 60_000;

type PublicKeys = Arc<HashMap<String, VerifyingKey>>;
type Sessions = Arc<Mutex<HashMap<String, Session>>>;

#[derive(Clone)]
struct Session {
    to_client: mpsc::Sender<Vec<u8>>,
    to_operator: Option<mpsc::Sender<Vec<u8>>>,
    pending_output: Vec<u8>,
}

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let config = ServerConfig::from_args(args).map_err(|err| err.to_string())?;
    let keys = Arc::new(config.load_public_keys().map_err(|err| err.to_string())?);
    let sessions = Sessions::default();
    let tcp = TcpListener::bind(&config.bind).await.map_err(|err| err.to_string())?;
    prepare_operator_socket(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;
    let ops = UnixListener::bind(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;

    eprintln!("listening on ws://{}/bepr/<client_id>", config.bind);
    eprintln!("operator socket {}", DEFAULT_OPERATOR_SOCKET);

    loop {
        tokio::select! {
            accepted = tcp.accept() => {
                let (stream, addr) = accepted.map_err(|err| err.to_string())?;
                let keys = keys.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_agent(stream, addr, keys, sessions).await {
                        eprintln!("{addr}: {err}");
                    }
                });
            }
            accepted = ops.accept() => {
                let (stream, _) = accepted.map_err(|err| err.to_string())?;
                let keys = keys.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_operator(stream, keys, sessions).await {
                        eprintln!("operator: {err}");
                    }
                });
            }
        }
    }
}

async fn handle_agent(
    stream: TcpStream,
    addr: SocketAddr,
    keys: PublicKeys,
    sessions: Sessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client_id = None;
    let ws = accept_hdr_async(stream, |req: &Request, resp: Response| {
        let Some(id) = req.uri().path().strip_prefix("/bepr/") else {
            return Err(error_response(StatusCode::NOT_FOUND, "unknown endpoint"));
        };
        if !keys.contains_key(id) {
            return Err(error_response(StatusCode::UNAUTHORIZED, "unknown client"));
        }
        client_id = Some(id.to_string());
        Ok(resp)
    })
    .await?;

    let client_id = client_id.ok_or("missing client id after handshake")?;
    let public_key = keys
        .get(&client_id)
        .copied()
        .ok_or("missing client key after handshake")?;
    let ws = authenticate(ws, public_key).await?;
    eprintln!("{addr}: authenticated {client_id}");

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (to_client_tx, mut to_client_rx) = mpsc::channel::<Vec<u8>>(32);
    let last_pong = Arc::new(Mutex::new(Instant::now()));
    let heartbeat_interval = heartbeat_interval();
    let heartbeat_timeout = heartbeat_timeout();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    {
        let mut sessions = sessions.lock().await;
        if sessions.contains_key(&client_id) {
            return Err(format!("client {client_id} is already connected").into());
        }
        sessions.insert(
            client_id.clone(),
            Session {
                to_client: to_client_tx,
                to_operator: None,
                pending_output: Vec::new(),
            },
        );
    }

    let client_for_writer = client_id.clone();
    let last_pong_for_writer = last_pong.clone();
    let write_task = tokio::spawn(async move {
        let mut shutdown_tx = Some(shutdown_tx);
        let mut heartbeat = interval(heartbeat_interval);
        loop {
            tokio::select! {
                Some(bytes) = to_client_rx.recv() => {
                    ws_tx.send(Message::Binary(bytes)).await?;
                }
                _ = heartbeat.tick() => {
                    if last_pong_for_writer.lock().await.elapsed() > heartbeat_timeout {
                        ws_tx.send(Message::Close(None)).await?;
                        if let Some(tx) = shutdown_tx.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    ws_tx.send(Message::Ping(Vec::new())).await?;
                }
                else => break,
            }
        }
        Ok::<_, tokio_tungstenite::tungstenite::Error>(())
    });

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                break;
            }
            msg = ws_rx.next() => {
                let Some(msg) = msg else {
                    break;
                };
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(err) => {
                        eprintln!("{addr}: {err}");
                        break;
                    }
                };
                let bytes = match msg {
                    Message::Binary(bytes) => bytes,
                    Message::Text(text) => text.into_bytes(),
                    Message::Pong(_) => {
                        *last_pong.lock().await = Instant::now();
                        continue;
                    }
                    Message::Close(_) => break,
                    _ => continue,
                };
                let operator = queue_client_output(&sessions, &client_id, &bytes).await;
                if let Some(operator) = operator {
                    let _ = operator.send(bytes).await;
                }
            }
        }
    }

    sessions.lock().await.remove(&client_id);
    write_task.abort();
    eprintln!("{addr}: disconnected {client_for_writer}");
    Ok(())
}

async fn handle_operator(
    mut stream: UnixStream,
    keys: PublicKeys,
    sessions: Sessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let command = read_line(&mut stream).await?;
    if command == "LIST" {
        return list_sessions(stream, keys, sessions).await;
    }
    let Some(client_id) = command.strip_prefix("CONNECT ") else {
        stream.write_all(b"ERR unknown command\n").await?;
        return Ok(());
    };
    let client_id = client_id.to_string();
    let (to_client, mut to_operator_rx, to_operator_tx, pending_output) = {
        let mut sessions = sessions.lock().await;
        let Some(session) = sessions.get_mut(&client_id) else {
            stream.write_all(b"ERR no such client\n").await?;
            return Ok(());
        };
        if session.to_operator.is_some() {
            stream.write_all(b"ERR already attached\n").await?;
            return Ok(());
        }
        let (to_operator_tx, to_operator_rx) = mpsc::channel::<Vec<u8>>(32);
        let pending_output = std::mem::take(&mut session.pending_output);
        session.to_operator = Some(to_operator_tx.clone());
        (
            session.to_client.clone(),
            to_operator_rx,
            to_operator_tx,
            pending_output,
        )
    };

    stream.write_all(b"OK\n").await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut write_task = tokio::spawn(async move {
        while let Some(bytes) = to_operator_rx.recv().await {
            writer.write_all(&bytes).await?;
            writer.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });

    if !pending_output.is_empty() {
        let _ = to_operator_tx.send(pending_output).await;
    }
    drop(to_operator_tx);

    let mut buf = [0_u8; 8192];
    loop {
        tokio::select! {
            result = &mut write_task => {
                result??;
                break;
            }
            read = reader.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                if to_client.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        }
    }

    if let Some(session) = sessions.lock().await.get_mut(&client_id) {
        session.to_operator = None;
    }
    write_task.abort();
    Ok(())
}

async fn queue_client_output(
    sessions: &Sessions,
    client_id: &str,
    bytes: &[u8],
) -> Option<mpsc::Sender<Vec<u8>>> {
    let mut sessions = sessions.lock().await;
    let session = sessions.get_mut(client_id)?;
    if let Some(operator) = session.to_operator.clone() {
        return Some(operator);
    }

    session.pending_output.extend_from_slice(bytes);
    if session.pending_output.len() > MAX_PENDING_OUTPUT {
        let excess = session.pending_output.len() - MAX_PENDING_OUTPUT;
        session.pending_output.drain(..excess);
    }
    None
}

async fn list_sessions(
    mut stream: UnixStream,
    keys: PublicKeys,
    sessions: Sessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut lines = Vec::new();
    {
        let sessions = sessions.lock().await;
        for client_id in keys.keys() {
            let state = if sessions.contains_key(client_id) {
                "connected"
            } else {
                "disconnected"
            };
            lines.push(format!("{client_id}\t{state}\n"));
        }
    }
    lines.sort();
    stream.write_all(b"OK\n").await?;
    for line in lines {
        stream.write_all(line.as_bytes()).await?;
    }
    stream.flush().await?;
    Ok(())
}

fn heartbeat_interval() -> Duration {
    Duration::from_millis(env_u64("BEPR_HEARTBEAT_INTERVAL_MS", HEARTBEAT_INTERVAL_MS))
}

fn heartbeat_timeout() -> Duration {
    Duration::from_millis(env_u64("BEPR_HEARTBEAT_TIMEOUT_MS", HEARTBEAT_TIMEOUT_MS))
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerConfig {
    pub bind: String,
    pub key_dir: String,
}

impl ServerConfig {
    fn from_args(args: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        match args.as_slice() {
            [] => Self::from_file(DEFAULT_SERVER_CONFIG),
            [flag, path] if flag == "--config" || flag == "-c" => Self::from_file(path),
            _ => Err("usage: bepr server [--config server.conf]".into()),
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::parse(&fs::read_to_string(path)?)
    }

    fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bind = None;
        let mut key_dir = None;

        for (idx, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("config:{} expected key = value", idx + 1).into());
            };
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("config:{} empty value for {key}", idx + 1).into());
            }
            match key {
                "bind" => bind = Some(value.to_string()),
                "key_dir" => key_dir = Some(value.to_string()),
                _ => return Err(format!("config:{} unknown key {key}", idx + 1).into()),
            }
        }

        Ok(Self {
            bind: bind.unwrap_or_else(|| DEFAULT_BIND.to_string()),
            key_dir: key_dir.ok_or("config missing key_dir")?,
        })
    }

    fn load_public_keys(&self) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error>> {
        load_key_dir(&self.key_dir)
    }
}

fn prepare_operator_socket(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    if Path::new(path).exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn load_key_dir(dir: &str) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error>> {
    let mut keys = HashMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("pub") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| format!("invalid public key filename {}", path.display()))?;
        let path = path.to_str().ok_or("public key path is not utf-8")?;
        keys.insert(id.to_string(), load_public_key(path)?);
    }
    Ok(keys)
}

fn load_public_key(path: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    parse_openssh_ed25519_public_key(&fs::read_to_string(path)?)
}

fn parse_openssh_ed25519_public_key(
    input: &str,
) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let mut fields = input.split_whitespace();
    let kind = fields.next().ok_or("missing public key kind")?;
    if kind != "ssh-ed25519" {
        return Err("public key must be ssh-ed25519".into());
    }
    let blob_b64 = fields.next().ok_or("missing public key body")?;
    let blob = Base64::decode_vec(blob_b64)?;
    let (inner_kind, rest) = read_ssh_string(&blob)?;
    if inner_kind != b"ssh-ed25519" {
        return Err("public key body kind mismatch".into());
    }
    let (key_bytes, rest) = read_ssh_string(rest)?;
    if !rest.is_empty() {
        return Err("public key body has trailing data".into());
    }
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "ed25519 public key must be 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}

async fn authenticate(
    mut ws: WebSocketStream<TcpStream>,
    public_key: VerifyingKey,
) -> Result<WebSocketStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let mut challenge = [0_u8; 32];
    getrandom::getrandom(&mut challenge)?;
    ws.send(Message::Binary(challenge.to_vec())).await?;

    let Some(msg) = ws.next().await else {
        return Err("client disconnected before signature".into());
    };
    let sig_bytes = match msg? {
        Message::Binary(bytes) => bytes,
        _ => return Err("expected binary signature".into()),
    };
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes")?;
    let signature = Signature::from_bytes(&sig_bytes);

    public_key.verify(&challenge, &signature)?;
    Ok(ws)
}

fn error_response(status: StatusCode, body: &str) -> ErrorResponse {
    http::Response::builder()
        .status(status)
        .body(Some(body.to_string()))
        .expect("static error response is valid")
}

async fn read_line(stream: &mut UnixStream) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
    }
    String::from_utf8(bytes)
        .map(|line| line.trim().to_string())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "line is not utf-8"))
}

fn read_ssh_string(input: &[u8]) -> Result<(&[u8], &[u8]), Box<dyn std::error::Error>> {
    if input.len() < 4 {
        return Err("short ssh string length".into());
    }
    let len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    let end = 4 + len;
    if input.len() < end {
        return Err("short ssh string body".into());
    }
    Ok((&input[4..end], &input[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn server_config_parse_reads_bind_and_key_dir() {
        let config = ServerConfig::parse(
            "
            bind = 0.0.0.0:8080
            key_dir = /etc/bepr/keys
            ",
        )
        .unwrap();

        assert_eq!(config.bind, "0.0.0.0:8080");
        assert_eq!(config.key_dir, "/etc/bepr/keys");
    }

    #[test]
    fn server_config_parse_defaults_bind() {
        let config = ServerConfig::parse("key_dir = /etc/bepr/keys").unwrap();

        assert_eq!(config.bind, DEFAULT_BIND);
        assert_eq!(config.key_dir, "/etc/bepr/keys");
    }

    #[test]
    fn server_config_parse_requires_key_dir() {
        assert!(ServerConfig::parse("bind = 127.0.0.1:8080").is_err());
    }

    #[test]
    fn server_config_parse_rejects_operator_socket_key() {
        assert!(ServerConfig::parse(
            "
            bind = 127.0.0.1:8080
            key_dir = /etc/bepr/keys
            operator_socket = /tmp/other.sock
            ",
        )
        .is_err());
    }

    #[test]
    fn parse_public_key_reads_openssh_ed25519() {
        let key = parse_openssh_ed25519_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI\n",
        )
        .unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn parse_public_key_rejects_non_ed25519_kind() {
        assert!(parse_openssh_ed25519_public_key("ssh-rsa AAAA").is_err());
    }

    #[test]
    fn load_public_keys_from_key_dir() {
        let dir = temp_dir("bepr-key-dir");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("laptop.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI\n",
        )
        .unwrap();
        fs::write(dir.join("ignored.txt"), "nope").unwrap();

        let keys = load_key_dir(dir.to_str().unwrap()).unwrap();
        assert!(keys.contains_key("laptop"));
        assert!(!keys.contains_key("ignored"));

        let _ = fs::remove_dir_all(dir);
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{}-{nanos}", std::process::id()))
    }
}
