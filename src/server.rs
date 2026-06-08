use std::{
    collections::HashMap,
    env,
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    sync::{mpsc, oneshot, Mutex},
    time::{interval, timeout},
};
use tokio_rustls::TlsAcceptor;

use crate::util::{log, read_line, read_ssh_string};
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
pub const DEFAULT_BIND: &str = "0.0.0.0:443";
const MAX_PENDING_OUTPUT: usize = 64 * 1024;
const KEY_RELOAD_INTERVAL_MS: u64 = 300_000;
const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const HEARTBEAT_TIMEOUT_MS: u64 = 60_000;

type PublicKeys = Arc<StdMutex<HashMap<String, VerifyingKey>>>;
type Sessions = Arc<Mutex<HashMap<String, Session>>>;


#[derive(Clone)]
struct Session {
    to_client: mpsc::Sender<Vec<u8>>,
    to_operator: Option<mpsc::Sender<Vec<u8>>>,
    pending_output: Vec<u8>,
}

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let config = ServerConfig::from_args(args).map_err(|err| err.to_string())?;
    let keys = Arc::new(StdMutex::new(
        config.load_public_keys().map_err(|err| err.to_string())?,
    ));
    let tls_acceptor = Arc::new(StdMutex::new(
        load_tls_acceptor(&config.tls_cert, &config.tls_key).map_err(|err| err.to_string())?,
    ));
    let sessions = Sessions::default();
    let tcp = TcpListener::bind(&config.bind).await.map_err(|err| err.to_string())?;
    prepare_operator_socket(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;
    let ops = UnixListener::bind(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;
    restrict_operator_socket(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;

    log(format!("listening on wss://{}/bepr/<client_id>", config.bind));
    log(format!("operator socket {}", DEFAULT_OPERATOR_SOCKET));

    {
        let keys = keys.clone();
        let tls_acceptor = tls_acceptor.clone();
        let sessions = sessions.clone();
        let key_dir = config.key_dir.clone();
        let tls_cert = config.tls_cert.clone();
        let tls_key = config.tls_key.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(KEY_RELOAD_INTERVAL_MS));
            loop {
                ticker.tick().await;
                match load_key_dir(&key_dir) {
                    Ok(reloaded) => *keys.lock().unwrap() = reloaded,
                    Err(err) => log(format!("key reload: {err}")),
                }
                match load_tls_acceptor(&tls_cert, &tls_key) {
                    Ok(reloaded) => *tls_acceptor.lock().unwrap() = reloaded,
                    Err(err) => log(format!("tls cert reload: {err}")),
                }
                let connected: Vec<String> = sessions.lock().await.keys().cloned().collect();
                if !connected.is_empty() {
                    log(format!("connected: {}", connected.join(", ")));
                }
            }
        });
    }

    loop {
        tokio::select! {
            accepted = tcp.accept() => {
                let (stream, addr) = accepted.map_err(|err| err.to_string())?;
                let acceptor = tls_acceptor.lock().unwrap().clone();
                let keys = keys.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(err) => { log(format!("{addr}: TLS: {err}")); return; }
                    };
                    if let Err(err) = handle_agent(tls_stream, addr, keys, sessions).await {
                        log(format!("{addr}: {err}"));
                    }
                });
            }
            accepted = ops.accept() => {
                let (stream, _) = accepted.map_err(|err| err.to_string())?;
                let keys = keys.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_operator(stream, keys, sessions).await {
                        log(format!("operator: {err}"));
                    }
                });
            }
        }
    }
}

async fn handle_agent<S>(
    stream: S,
    addr: SocketAddr,
    keys: PublicKeys,
    sessions: Sessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client_id = Arc::new(StdMutex::new(None));
    let handshake_keys = keys.clone();
    let handshake_client_id = client_id.clone();
    let ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
        let Some(id) = req.uri().path().strip_prefix("/bepr/") else {
            return Err(error_response(StatusCode::NOT_FOUND, "unknown endpoint"));
        };
        if !handshake_keys.lock().unwrap().contains_key(id) {
            return Err(error_response(StatusCode::UNAUTHORIZED, "unknown client"));
        }
        *handshake_client_id.lock().unwrap() = Some(id.to_string());
        Ok(resp)
    })
    .await?;

    let client_id = client_id
        .lock()
        .unwrap()
        .clone()
        .ok_or("missing client id after handshake")?;
    let public_key = keys
        .lock()
        .unwrap()
        .get(&client_id)
        .copied()
        .ok_or("missing client key after handshake")?;
    let ws = timeout(Duration::from_secs(30), authenticate(ws, public_key))
        .await
        .map_err(|_| "authentication timed out")??;
    log(format!("{addr}: authenticated {client_id}"));

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
                        log(format!("{addr}: {err}"));
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
    log(format!("{addr}: disconnected {client_for_writer}"));
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
    let (to_client, mut to_operator_rx, pending_output) = {
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
        session.to_operator = Some(to_operator_tx);
        (session.to_client.clone(), to_operator_rx, pending_output)
    };

    stream.write_all(b"OK\n").await?;
    let (mut reader, mut writer) = stream.into_split();

    if !pending_output.is_empty() {
        writer.write_all(&pending_output).await?;
        writer.flush().await?;
    }

    let mut write_task = tokio::spawn(async move {
        while let Some(bytes) = to_operator_rx.recv().await {
            writer.write_all(&bytes).await?;
            writer.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });

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
        let client_ids = keys.lock().unwrap().keys().cloned().collect::<Vec<_>>();
        let sessions = sessions.lock().await;
        for client_id in client_ids {
            let state = if sessions.contains_key(&client_id) {
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
    pub tls_cert: String,
    pub tls_key: String,
}

impl ServerConfig {
    fn from_args(args: Vec<String>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match args.as_slice() {
            [] => Self::from_file(DEFAULT_SERVER_CONFIG),
            [flag, path] if flag == "--config" || flag == "-c" => Self::from_file(path),
            _ => Err("usage: bepr server [--config server.conf]".into()),
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::parse(&fs::read_to_string(path)?)
    }

    fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut bind = None;
        let mut key_dir = None;
        let mut tls_cert = None;
        let mut tls_key = None;

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
                "tls_cert" => tls_cert = Some(value.to_string()),
                "tls_key" => tls_key = Some(value.to_string()),
                _ => return Err(format!("config:{} unknown key {key}", idx + 1).into()),
            }
        }

        Ok(Self {
            bind: bind.unwrap_or_else(|| DEFAULT_BIND.to_string()),
            key_dir: key_dir.ok_or("config missing key_dir")?,
            tls_cert: tls_cert.ok_or("config missing tls_cert")?,
            tls_key: tls_key.ok_or("config missing tls_key")?,
        })
    }

    fn load_public_keys(&self) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error + Send + Sync>> {
        load_key_dir(&self.key_dir)
    }
}

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or("no private key found in tls_key file")?;

    let config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn prepare_operator_socket(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(path);
    Ok(())
}

fn restrict_operator_socket(path: &str) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn load_key_dir(dir: &str) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error + Send + Sync>> {
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

fn load_public_key(path: &str) -> Result<VerifyingKey, Box<dyn std::error::Error + Send + Sync>> {
    parse_openssh_ed25519_public_key(&fs::read_to_string(path)?)
}

fn parse_openssh_ed25519_public_key(
    input: &str,
) -> Result<VerifyingKey, Box<dyn std::error::Error + Send + Sync>> {
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

async fn authenticate<S>(
    mut ws: WebSocketStream<S>,
    public_key: VerifyingKey,
) -> Result<WebSocketStream<S>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::AsyncReadExt,
        net::UnixStream,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn server_config_parse_reads_all_fields() {
        let config = ServerConfig::parse(
            "
            bind = 0.0.0.0:8080
            key_dir = /etc/bepr/keys
            tls_cert = /etc/bepr/tls/cert.pem
            tls_key = /etc/bepr/tls/key.pem
            ",
        )
        .unwrap();

        assert_eq!(config.bind, "0.0.0.0:8080");
        assert_eq!(config.key_dir, "/etc/bepr/keys");
        assert_eq!(config.tls_cert, "/etc/bepr/tls/cert.pem");
        assert_eq!(config.tls_key, "/etc/bepr/tls/key.pem");
    }

    #[test]
    fn server_config_parse_defaults_bind() {
        let config = ServerConfig::parse(
            "key_dir = /etc/bepr/keys\ntls_cert = /etc/bepr/tls/cert.pem\ntls_key = /etc/bepr/tls/key.pem\n"
        ).unwrap();

        assert_eq!(config.bind, DEFAULT_BIND);
        assert_eq!(config.key_dir, "/etc/bepr/keys");
    }

    #[test]
    fn server_config_parse_requires_key_dir() {
        assert!(ServerConfig::parse(
            "bind = 127.0.0.1:8080\ntls_cert = /etc/bepr/tls/cert.pem\ntls_key = /etc/bepr/tls/key.pem\n"
        ).is_err());
    }

    #[test]
    fn server_config_parse_requires_tls_cert() {
        assert!(ServerConfig::parse(
            "bind = 127.0.0.1:8080\nkey_dir = /etc/bepr/keys\ntls_key = /etc/bepr/tls/key.pem\n"
        ).is_err());
    }

    #[test]
    fn server_config_parse_requires_tls_key() {
        assert!(ServerConfig::parse(
            "bind = 127.0.0.1:8080\nkey_dir = /etc/bepr/keys\ntls_cert = /etc/bepr/tls/cert.pem\n"
        ).is_err());
    }

    #[test]
    fn server_config_parse_rejects_unknown_key() {
        assert!(ServerConfig::parse(
            "
            bind = 127.0.0.1:8080
            key_dir = /etc/bepr/keys
            tls_cert = /etc/bepr/tls/cert.pem
            tls_key = /etc/bepr/tls/key.pem
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

    #[tokio::test]
    async fn list_sessions_uses_current_public_keys_map() {
        let keys = Arc::new(StdMutex::new(HashMap::from([(
            "laptop".to_string(),
            parse_openssh_ed25519_public_key(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI\n",
            )
            .unwrap(),
        )])));
        let sessions = Sessions::default();

        let (mut client, server) = UnixStream::pair().unwrap();
        let keys_for_task = keys.clone();
        let sessions_for_task = sessions.clone();
        let task = tokio::spawn(async move {
            list_sessions(server, keys_for_task, sessions_for_task).await.unwrap();
        });

        let mut first = Vec::new();
        client.read_to_end(&mut first).await.unwrap();
        task.await.unwrap();
        let first = String::from_utf8(first).unwrap();
        assert!(first.contains("laptop\tdisconnected"));

        *keys.lock().unwrap() = HashMap::from([(
            "pi".to_string(),
            parse_openssh_ed25519_public_key(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI\n",
            )
            .unwrap(),
        )]);

        let (mut client, server) = UnixStream::pair().unwrap();
        let keys_for_task = keys.clone();
        let sessions_for_task = sessions.clone();
        let task = tokio::spawn(async move {
            list_sessions(server, keys_for_task, sessions_for_task).await.unwrap();
        });

        let mut second = Vec::new();
        client.read_to_end(&mut second).await.unwrap();
        task.await.unwrap();
        let second = String::from_utf8(second).unwrap();
        assert!(second.contains("pi\tdisconnected"));
        assert!(!second.contains("laptop\tdisconnected"));
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{}-{nanos}", std::process::id()))
    }
}
