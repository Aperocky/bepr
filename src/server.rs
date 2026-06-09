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

use crate::config::{load_key_dir, ServerConfig};
use crate::util::{log, read_line};
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
const MAX_PENDING_OUTPUT: usize = 64 * 1024;
const KEY_RELOAD_INTERVAL_MS: u64 = 300_000;
const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const HEARTBEAT_TIMEOUT_MS: u64 = 60_000;
const HANDSHAKE_TIMEOUT_MS: u64 = 5_000;

type PublicKeys = Arc<StdMutex<HashMap<String, VerifyingKey>>>;
type Sessions = Arc<Mutex<HashMap<String, Session>>>;

enum ConnPath {
    Client(String),
    User(String),
}

#[derive(Clone)]
struct Session {
    to_client: mpsc::Sender<Vec<u8>>,
    to_operator: Option<mpsc::Sender<Vec<u8>>>,
    pending_output: Vec<u8>,
}

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let config = ServerConfig::from_args(args).map_err(|err| err.to_string())?;
    let keys = Arc::new(StdMutex::new(
        config.load_public_keys().unwrap_or_else(|err| { log(format!("key_dir: {err}")); Default::default() }),
    ));
    let user_keys = Arc::new(StdMutex::new(
        config.load_user_keys().unwrap_or_else(|err| { log(format!("user_key_dir: {err}")); Default::default() }),
    ));
    let tls_acceptor = Arc::new(StdMutex::new(
        load_tls_acceptor(&config.tls_cert, &config.tls_key).map_err(|err| err.to_string())?,
    ));
    let sessions = Sessions::default();
    let tcp = TcpListener::bind(&config.bind).await.map_err(|err| err.to_string())?;
    prepare_operator_socket(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;
    let ops = UnixListener::bind(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;
    restrict_operator_socket(DEFAULT_OPERATOR_SOCKET).map_err(|err| err.to_string())?;

    log(format!("listening on wss://{}/bepr/client/<client_id>", config.bind));
    if config.user_key_dir.is_some() {
        log(format!("user endpoint wss://{}/bepr/user/<user_id>", config.bind));
    }
    log(format!("operator socket {}", DEFAULT_OPERATOR_SOCKET));

    {
        let keys = keys.clone();
        let user_keys = user_keys.clone();
        let tls_acceptor = tls_acceptor.clone();
        let sessions = sessions.clone();
        let key_dir = config.key_dir.clone();
        let user_key_dir = config.user_key_dir.clone();
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
                if let Some(ref dir) = user_key_dir {
                    match load_key_dir(dir) {
                        Ok(reloaded) => *user_keys.lock().unwrap() = reloaded,
                        Err(err) => log(format!("user key reload: {err}")),
                    }
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
                let user_keys = user_keys.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let tls_stream = match timeout(handshake_timeout(), acceptor.accept(stream)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(err)) => { log(format!("{addr}: TLS: {err}")); return; }
                        Err(_) => { log(format!("{addr}: TLS handshake timed out")); return; }
                    };
                    accept_connection(tls_stream, addr, keys, user_keys, sessions).await;
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

async fn accept_connection<S>(
    stream: S,
    addr: SocketAddr,
    client_keys: PublicKeys,
    user_keys: PublicKeys,
    sessions: Sessions,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_path = Arc::new(StdMutex::new(None::<ConnPath>));
    let cp = conn_path.clone();
    let cp_client_keys = client_keys.clone();
    let cp_user_keys = user_keys.clone();

    let ws = timeout(handshake_timeout(), accept_hdr_async(stream, move |req: &Request, resp: Response| {
        let path = req.uri().path();
        let conn = if let Some(id) = path.strip_prefix("/bepr/client/") {
            if id.is_empty() || id.contains('/') {
                return Err(error_response(StatusCode::BAD_REQUEST, "invalid client id"));
            }
            if !cp_client_keys.lock().unwrap().contains_key(id) {
                return Err(error_response(StatusCode::UNAUTHORIZED, "unknown client"));
            }
            ConnPath::Client(id.to_string())
        } else if let Some(id) = path.strip_prefix("/bepr/user/") {
            if id.is_empty() || id.contains('/') {
                return Err(error_response(StatusCode::BAD_REQUEST, "invalid user id"));
            }
            if !cp_user_keys.lock().unwrap().contains_key(id) {
                return Err(error_response(StatusCode::UNAUTHORIZED, "unknown user"));
            }
            ConnPath::User(id.to_string())
        } else if let Some(id) = path.strip_prefix("/bepr/") {
            if id.is_empty() || id.contains('/') || id == "client" || id == "user" {
                return Err(error_response(StatusCode::BAD_REQUEST, "invalid client id"));
            }
            if !cp_client_keys.lock().unwrap().contains_key(id) {
                return Err(error_response(StatusCode::UNAUTHORIZED, "unknown client"));
            }
            ConnPath::Client(id.to_string())
        } else {
            return Err(error_response(StatusCode::NOT_FOUND, "unknown endpoint"));
        };
        *cp.lock().unwrap() = Some(conn);
        Ok(resp)
    })).await;

    let ws = match ws {
        Ok(Ok(ws)) => ws,
        Ok(Err(_)) => return,
        Err(_) => { log(format!("{addr}: WebSocket handshake timed out")); return; }
    };

    let conn = conn_path.lock().unwrap().take();
    match conn {
        Some(ConnPath::Client(id)) => {
            let Some(key) = client_keys.lock().unwrap().get(&id).copied() else { return; };
            if let Err(err) = handle_agent(ws, addr, id, key, sessions).await {
                log(format!("{addr}: {err}"));
            }
        }
        Some(ConnPath::User(id)) => {
            let Some(key) = user_keys.lock().unwrap().get(&id).copied() else { return; };
            if let Err(err) = handle_network_operator(ws, addr, id, key, client_keys, sessions).await {
                log(format!("{addr}: {err}"));
            }
        }
        None => {}
    }
}

async fn handle_agent<S>(
    ws: WebSocketStream<S>,
    addr: SocketAddr,
    client_id: String,
    public_key: VerifyingKey,
    sessions: Sessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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

async fn handle_network_operator<S>(
    ws: WebSocketStream<S>,
    addr: SocketAddr,
    user_id: String,
    public_key: VerifyingKey,
    client_keys: PublicKeys,
    sessions: Sessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut ws = timeout(Duration::from_secs(30), authenticate(ws, public_key))
        .await
        .map_err(|_| "authentication timed out")??;
    log(format!("{addr}: operator authenticated {user_id}"));

    let Some(msg) = ws.next().await else {
        return Err("operator disconnected before command".into());
    };
    let command = match msg? {
        Message::Binary(b) => String::from_utf8(b)?,
        Message::Text(t) => t.to_string(),
        _ => return Err("expected command".into()),
    };
    let command = command.trim();

    if command == "LIST" {
        return list_network_sessions(ws, client_keys, sessions).await;
    }

    let Some(client_id) = command.strip_prefix("CONNECT ") else {
        ws.send(Message::Binary(b"ERR unknown command\n".to_vec())).await?;
        return Ok(());
    };
    let client_id = client_id.trim().to_string();

    let (to_client, mut to_operator_rx, pending_output) = {
        let mut sessions = sessions.lock().await;
        let Some(session) = sessions.get_mut(&client_id) else {
            ws.send(Message::Binary(b"ERR no such client\n".to_vec())).await?;
            return Ok(());
        };
        if session.to_operator.is_some() {
            ws.send(Message::Binary(b"ERR already attached\n".to_vec())).await?;
            return Ok(());
        }
        let (to_operator_tx, to_operator_rx) = mpsc::channel::<Vec<u8>>(32);
        let pending_output = std::mem::take(&mut session.pending_output);
        session.to_operator = Some(to_operator_tx);
        (session.to_client.clone(), to_operator_rx, pending_output)
    };

    if ws.send(Message::Binary(b"OK\n".to_vec())).await.is_err()
        || (!pending_output.is_empty()
            && ws.send(Message::Binary(pending_output)).await.is_err())
    {
        if let Some(s) = sessions.lock().await.get_mut(&client_id) {
            s.to_operator = None;
        }
        return Ok(());
    }

    let last_pong = Arc::new(Mutex::new(Instant::now()));
    let last_pong_for_task = last_pong.clone();
    let heartbeat_interval = heartbeat_interval();
    let heartbeat_timeout = heartbeat_timeout();

    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut write_task = tokio::spawn(async move {
        let mut heartbeat = interval(heartbeat_interval);
        loop {
            tokio::select! {
                bytes = to_operator_rx.recv() => {
                    let Some(bytes) = bytes else { break; };
                    ws_tx.send(Message::Binary(bytes)).await?;
                }
                _ = heartbeat.tick() => {
                    if last_pong_for_task.lock().await.elapsed() > heartbeat_timeout {
                        break;
                    }
                    ws_tx.send(Message::Ping(vec![])).await?;
                }
            }
        }
        Ok::<_, tokio_tungstenite::tungstenite::Error>(())
    });

    loop {
        tokio::select! {
            _ = &mut write_task => { break; }
            msg = ws_rx.next() => {
                let Some(msg) = msg else { break; };
                let Ok(msg) = msg else { break; };
                match msg {
                    Message::Binary(bytes) => {
                        if to_client.send(bytes).await.is_err() { break; }
                    }
                    Message::Text(text) => {
                        if to_client.send(text.into_bytes()).await.is_err() { break; }
                    }
                    Message::Pong(_) => {
                        *last_pong.lock().await = Instant::now();
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    if let Some(session) = sessions.lock().await.get_mut(&client_id) {
        session.to_operator = None;
    }
    write_task.abort();
    log(format!("{addr}: operator {user_id} detached from {client_id}"));
    Ok(())
}

async fn list_network_sessions<S>(
    mut ws: WebSocketStream<S>,
    client_keys: PublicKeys,
    sessions: Sessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut lines = Vec::new();
    {
        let ids = client_keys.lock().unwrap().keys().cloned().collect::<Vec<_>>();
        let sessions = sessions.lock().await;
        for id in ids {
            let state = if sessions.contains_key(&id) { "connected" } else { "disconnected" };
            lines.push(format!("{id}\t{state}\n"));
        }
    }
    lines.sort();
    let mut response = b"OK\n".to_vec();
    for line in lines {
        response.extend_from_slice(line.as_bytes());
    }
    ws.send(Message::Binary(response)).await?;
    ws.send(Message::Close(None)).await?;
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

fn handshake_timeout() -> Duration {
    Duration::from_millis(env_u64("BEPR_HANDSHAKE_TIMEOUT_MS", HANDSHAKE_TIMEOUT_MS))
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
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
    use crate::config::parse_openssh_ed25519_public_key;
    use tokio::{io::AsyncReadExt, net::UnixStream};
    use std::time::{SystemTime, UNIX_EPOCH};
    use ed25519_dalek::Signer;
    use tokio_tungstenite::{accept_async, client_async};

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    async fn ws_pair() -> (
        WebSocketStream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        WebSocketStream<impl AsyncRead + AsyncWrite + Unpin + Send>,
    ) {
        let (server_io, client_io) = tokio::io::duplex(65536);
        let (server_res, client_res) = tokio::join!(
            accept_async(server_io),
            client_async("ws://localhost/", client_io),
        );
        (server_res.unwrap(), client_res.unwrap().0)
    }

    async fn do_auth(ws: &mut WebSocketStream<impl AsyncRead + AsyncWrite + Unpin>) {
        let signing_key = test_signing_key();
        let challenge = match ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            m => panic!("expected challenge, got {m:?}"),
        };
        let sig: ed25519_dalek::Signature = signing_key.sign(&challenge);
        ws.send(Message::Binary(sig.to_bytes().to_vec())).await.unwrap();
    }

    async fn test_sessions_with_client(client_id: &str) -> (Sessions, mpsc::Receiver<Vec<u8>>) {
        let sessions = Sessions::default();
        let (to_client_tx, to_client_rx) = mpsc::channel::<Vec<u8>>(32);
        sessions.lock().await.insert(client_id.to_string(), Session {
            to_client: to_client_tx,
            to_operator: None,
            pending_output: Vec::new(),
        });
        (sessions, to_client_rx)
    }

    #[tokio::test]
    async fn network_operator_clears_to_operator_on_abrupt_disconnect() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let (sessions, _client_rx) = test_sessions_with_client("testclient").await;
        let client_keys: PublicKeys = Arc::new(StdMutex::new(HashMap::new()));

        let (server_ws, mut client_ws) = ws_pair().await;
        let sessions_c = sessions.clone();
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let handle = tokio::spawn(async move {
            handle_network_operator(server_ws, addr, "user1".into(), verifying_key, client_keys, sessions_c).await
        });

        do_auth(&mut client_ws).await;
        client_ws.send(Message::Binary(b"CONNECT testclient".to_vec())).await.unwrap();

        match client_ws.next().await.unwrap().unwrap() {
            Message::Binary(b) if b == b"OK\n" => {}
            m => panic!("expected OK, got {m:?}"),
        }

        assert!(sessions.lock().await.get("testclient").unwrap().to_operator.is_some());

        // Abrupt disconnect — drop without sending Close
        drop(client_ws);

        handle.await.unwrap().ok(); // may return error, that's fine
        assert!(sessions.lock().await.get("testclient").unwrap().to_operator.is_none(),
            "to_operator must be cleared after operator disconnects");
    }

    #[tokio::test]
    async fn network_operator_allows_reconnect_after_disconnect() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let (sessions, _client_rx) = test_sessions_with_client("testclient").await;
        let client_keys: PublicKeys = Arc::new(StdMutex::new(HashMap::new()));
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        // First operator connects then abruptly drops
        {
            let (server_ws, mut client_ws) = ws_pair().await;
            let sessions_c = sessions.clone();
            let vk = verifying_key;
            let ck = client_keys.clone();
            let h = tokio::spawn(async move {
                handle_network_operator(server_ws, addr, "user1".into(), vk, ck, sessions_c).await
            });
            do_auth(&mut client_ws).await;
            client_ws.send(Message::Binary(b"CONNECT testclient".to_vec())).await.unwrap();
            match client_ws.next().await.unwrap().unwrap() {
                Message::Binary(b) if b == b"OK\n" => {}
                m => panic!("expected OK, got {m:?}"),
            }
            drop(client_ws);
            h.await.unwrap().ok();
        }

        // Second operator can now attach without "ERR already attached"
        let (server_ws, mut client_ws) = ws_pair().await;
        let sessions_c = sessions.clone();
        let ck = client_keys.clone();
        let h = tokio::spawn(async move {
            handle_network_operator(server_ws, addr, "user1".into(), verifying_key, ck, sessions_c).await
        });
        do_auth(&mut client_ws).await;
        client_ws.send(Message::Binary(b"CONNECT testclient".to_vec())).await.unwrap();
        let reply = match client_ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            m => panic!("unexpected message {m:?}"),
        };
        assert_eq!(reply, b"OK\n", "second operator should attach without 'already attached' error");
        drop(client_ws);
        h.await.unwrap().ok();
    }

    #[tokio::test]
    async fn network_operator_heartbeat_detaches_unresponsive_operator() {
        unsafe {
            std::env::set_var("BEPR_HEARTBEAT_INTERVAL_MS", "50");
            std::env::set_var("BEPR_HEARTBEAT_TIMEOUT_MS", "120");
        }

        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let (sessions, _client_rx) = test_sessions_with_client("testclient").await;
        let client_keys: PublicKeys = Arc::new(StdMutex::new(HashMap::new()));
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        let (server_ws, mut client_ws) = ws_pair().await;
        let sessions_c = sessions.clone();
        let handle = tokio::spawn(async move {
            handle_network_operator(server_ws, addr, "user1".into(), verifying_key, client_keys, sessions_c).await
        });

        do_auth(&mut client_ws).await;
        client_ws.send(Message::Binary(b"CONNECT testclient".to_vec())).await.unwrap();
        match client_ws.next().await.unwrap().unwrap() {
            Message::Binary(b) if b == b"OK\n" => {}
            m => panic!("expected OK, got {m:?}"),
        }

        // Stop responding to pings (hold the ws but don't read)
        tokio::time::sleep(Duration::from_millis(400)).await;

        handle.await.unwrap().ok();
        assert!(sessions.lock().await.get("testclient").unwrap().to_operator.is_none(),
            "heartbeat timeout must clear to_operator");

        unsafe {
            std::env::remove_var("BEPR_HEARTBEAT_INTERVAL_MS");
            std::env::remove_var("BEPR_HEARTBEAT_TIMEOUT_MS");
        }
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

}
