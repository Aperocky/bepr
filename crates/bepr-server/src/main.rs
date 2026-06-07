use std::{collections::HashMap, env, fs, net::SocketAddr, sync::Arc};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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

type Clients = Arc<HashMap<String, VerifyingKey>>;
const DEFAULT_SERVER_CONFIG: &str = "/etc/bepr/server.conf";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::from_args(env::args().skip(1).collect())?;
    let clients = Arc::new(config.load_clients()?);
    let listener = TcpListener::bind(&config.bind).await?;

    eprintln!("listening on ws://{}/agent/<client_id>", config.bind);

    loop {
        let (stream, addr) = listener.accept().await?;
        let clients = clients.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(stream, addr, clients).await {
                eprintln!("{addr}: {err}");
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    addr: SocketAddr,
    clients: Clients,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client_id = None;
    let ws = accept_hdr_async(stream, |req: &Request, resp: Response| {
        let path = req.uri().path();
        let Some(id) = path.strip_prefix("/agent/") else {
            return Err(error_response(StatusCode::NOT_FOUND, "unknown endpoint"));
        };
        if !clients.contains_key(id) {
            return Err(error_response(StatusCode::UNAUTHORIZED, "unknown client"));
        }
        client_id = Some(id.to_string());
        Ok(resp)
    })
    .await?;

    let client_id = client_id.ok_or("missing client id after handshake")?;
    let public_key = clients
        .get(&client_id)
        .copied()
        .ok_or("missing client key after handshake")?;

    let ws = authenticate(ws, public_key).await?;
    eprintln!("{addr}: authenticated {client_id}");
    pipe_stdio(ws).await?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ServerConfig {
    bind: String,
    clients: Vec<ClientKeyPath>,
}

#[derive(Debug, PartialEq, Eq)]
struct ClientKeyPath {
    id: String,
    path: String,
}

impl ServerConfig {
    fn from_args(args: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        match args.as_slice() {
            [] => Self::from_file(DEFAULT_SERVER_CONFIG),
            [flag, path] if flag == "--config" || flag == "-c" => Self::from_file(path),
            [bind, clients_path] => Ok(Self {
                bind: bind.clone(),
                clients: legacy_client_key_paths(clients_path)?,
            }),
            _ => Err("usage: bepr-server [--config server.conf]".into()),
        }
    }

    fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::parse(&fs::read_to_string(path)?)
    }

    fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bind = None;
        let mut clients = Vec::new();

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
                "client" => clients.push(parse_client_entry(value, idx + 1)?),
                _ => return Err(format!("config:{} unknown key {key}", idx + 1).into()),
            }
        }

        if clients.is_empty() {
            return Err("config missing client entries".into());
        }

        Ok(Self {
            bind: bind.unwrap_or_else(|| "127.0.0.1:8080".to_string()),
            clients,
        })
    }

    fn load_clients(&self) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error>> {
        let mut clients = HashMap::new();
        for client in &self.clients {
            clients.insert(client.id.clone(), load_public_key(&client.path)?);
        }
        Ok(clients)
    }
}

fn parse_client_entry(value: &str, line: usize) -> Result<ClientKeyPath, Box<dyn std::error::Error>> {
    let Some((id, path)) = value.split_once(',') else {
        return Err(format!("config:{line} client must be client_id,path").into());
    };
    let id = id.trim();
    let path = path.trim();
    if id.is_empty() || path.is_empty() {
        return Err(format!("config:{line} client must be client_id,path").into());
    }
    Ok(ClientKeyPath {
        id: id.to_string(),
        path: path.to_string(),
    })
}

fn legacy_client_key_paths(path: &str) -> Result<Vec<ClientKeyPath>, Box<dyn std::error::Error>> {
    let mut clients = Vec::new();
    for (idx, line) in fs::read_to_string(path)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let id = fields
            .next()
            .ok_or_else(|| format!("{}:{} missing client id", path, idx + 1))?;
        let key_path = fields
            .next()
            .ok_or_else(|| format!("{}:{} missing public key path", path, idx + 1))?;
        if fields.next().is_some() {
            return Err(format!("{}:{} too many fields", path, idx + 1).into());
        }
        clients.push(ClientKeyPath {
            id: id.to_string(),
            path: key_path.to_string(),
        });
    }
    Ok(clients)
}

fn error_response(status: StatusCode, body: &str) -> ErrorResponse {
    http::Response::builder()
        .status(status)
        .body(Some(body.to_string()))
        .expect("static error response is valid")
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

async fn pipe_stdio(
    ws: WebSocketStream<TcpStream>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let to_client = tokio::spawn(async move {
        let mut buf = [0_u8; 8192];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ws_tx.send(Message::Binary(buf[..n].to_vec())).await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });

    while let Some(msg) = ws_rx.next().await {
        match msg? {
            Message::Binary(bytes) => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            Message::Text(text) => {
                stdout.write_all(text.as_bytes()).await?;
                stdout.flush().await?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    to_client.abort();
    Ok(())
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

fn read_ssh_string(input: &[u8]) -> Result<(&[u8], &[u8]), Box<dyn std::error::Error>> {
    if input.len() < 4 {
        return Err("short ssh string length".into());
    }
    let len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    let start = 4;
    let end = start + len;
    if input.len() < end {
        return Err("short ssh string body".into());
    }
    Ok((&input[start..end], &input[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn server_config_parse_reads_bind_and_clients() {
        let config = ServerConfig::parse(
            "
            bind = 0.0.0.0:8080
            client = default, /etc/bepr/keys/default.pub
            client = laptop,/etc/bepr/keys/laptop.pub
            ",
        )
        .unwrap();

        assert_eq!(config.bind, "0.0.0.0:8080");
        assert_eq!(
            config.clients,
            vec![
                ClientKeyPath {
                    id: "default".to_string(),
                    path: "/etc/bepr/keys/default.pub".to_string(),
                },
                ClientKeyPath {
                    id: "laptop".to_string(),
                    path: "/etc/bepr/keys/laptop.pub".to_string(),
                },
            ]
        );
    }

    #[test]
    fn server_config_parse_requires_client() {
        assert!(ServerConfig::parse("bind = 127.0.0.1:8080").is_err());
    }

    #[test]
    fn parse_public_key_reads_openssh_ed25519() {
        let key = parse_openssh_ed25519_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI\n",
        )
        .unwrap();
        assert_eq!(
            key.as_bytes(),
            &[
                0xf3, 0xe2, 0xc6, 0xd0, 0xc5, 0x48, 0x83, 0xce, 0xf9, 0x87, 0xe8, 0x0f, 0xca,
                0xa4, 0xd8, 0x04, 0x05, 0x34, 0x07, 0xe1, 0xec, 0xdb, 0xa2, 0xcd, 0x5e, 0x5c,
                0x75, 0x0d, 0x22, 0x8b, 0x80, 0x88,
            ]
        );
    }

    #[test]
    fn load_server_config_clients_from_public_key_paths() {
        let key_path = temp_file("bepr-server-client-key");
        let mut key_file = fs::File::create(&key_path).unwrap();
        writeln!(
            key_file,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI"
        )
        .unwrap();
        let config = ServerConfig {
            bind: "127.0.0.1:8080".to_string(),
            clients: vec![ClientKeyPath {
                id: "default".to_string(),
                path: key_path.to_string_lossy().to_string(),
            }],
        };

        let clients = config.load_clients().unwrap();
        assert!(clients.contains_key("default"));

        let _ = fs::remove_file(key_path);
    }

    fn temp_file(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("{name}-{}-{nanos}.txt", std::process::id()))
    }
}
