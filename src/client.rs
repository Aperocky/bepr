use std::{fs, time::Duration};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::mpsc,
    time::sleep,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const DEFAULT_CLIENT_CONFIG: &str = "/etc/bepr/client.conf";

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let config = ClientConfig::from_args(args).map_err(|err| err.to_string())?;
    let key = config.load_signing_key().map_err(|err| err.to_string())?;

    loop {
        if let Err(err) = run_once(&config.server, &key, &config.shell).await {
            eprintln!("{err}");
        }
        sleep(Duration::from_secs(3)).await;
    }
}

async fn run_once(
    server: &str,
    key: &SigningKey,
    shell: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut ws, _) = connect_async(server).await?;

    let Some(challenge) = ws.next().await else {
        return Err("server disconnected before challenge".into());
    };
    let challenge = match challenge? {
        Message::Binary(bytes) => bytes,
        _ => return Err("expected binary challenge".into()),
    };
    ws.send(Message::Binary(key.sign(&challenge).to_bytes().to_vec()))
        .await?;

    let mut child = Command::new(shell)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let mut child_stdin = child.stdin.take().ok_or("missing child stdin")?;
    let mut child_stdout = child.stdout.take().ok_or("missing child stdout")?;
    let mut child_stderr = child.stderr.take().ok_or("missing child stderr")?;
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(32);

    let stdout_tx = out_tx.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0_u8; 8192];
        loop {
            let n = child_stdout.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if stdout_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    });

    let stderr_task = tokio::spawn(async move {
        let mut buf = [0_u8; 8192];
        loop {
            let n = child_stderr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if out_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    });

    let to_ws = tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            ws_tx.send(Message::Binary(bytes)).await?;
        }
        Ok::<_, tokio_tungstenite::tungstenite::Error>(())
    });

    while let Some(msg) = ws_rx.next().await {
        match msg? {
            Message::Binary(bytes) => child_stdin.write_all(&bytes).await?,
            Message::Text(text) => child_stdin.write_all(text.as_bytes()).await?,
            Message::Close(_) => break,
            _ => {}
        }
    }

    let _ = child.kill().await;
    stdout_task.abort();
    stderr_task.abort();
    to_ws.abort();
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ClientConfig {
    server: String,
    private_key: PrivateKeyConfig,
    shell: String,
}

#[derive(Debug, PartialEq, Eq)]
enum PrivateKeyConfig {
    Path(String),
    Hex(String),
}

impl ClientConfig {
    fn from_args(args: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        match args.as_slice() {
            [] => Self::from_file(DEFAULT_CLIENT_CONFIG),
            [flag, path] if flag == "--config" || flag == "-c" => Self::from_file(path),
            [server, private_key] => Ok(Self {
                server: server.clone(),
                private_key: PrivateKeyConfig::Hex(private_key.clone()),
                shell: default_shell(),
            }),
            [server, private_key, shell] => Ok(Self {
                server: server.clone(),
                private_key: PrivateKeyConfig::Hex(private_key.clone()),
                shell: shell.clone(),
            }),
            _ => Err("invalid client arguments".into()),
        }
    }

    fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::parse(&fs::read_to_string(path)?)
    }

    fn load_signing_key(&self) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
        match &self.private_key {
            PrivateKeyConfig::Path(path) => load_openssh_ed25519_private_key(path),
            PrivateKeyConfig::Hex(hex) => signing_key_from_hex(hex),
        }
    }

    fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut server = None;
        let mut private_key_path = None;
        let mut shell = None;

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
                "server" => server = Some(value.to_string()),
                "private_key_path" => private_key_path = Some(value.to_string()),
                "shell" => shell = Some(value.to_string()),
                _ => return Err(format!("config:{} unknown key {key}", idx + 1).into()),
            }
        }

        Ok(Self {
            server: server.ok_or("config missing server")?,
            private_key: PrivateKeyConfig::Path(
                private_key_path.ok_or("config missing private_key_path")?,
            ),
            shell: shell.unwrap_or_else(default_shell),
        })
    }
}

fn default_shell() -> String {
    "/bin/sh".to_string()
}

pub fn keygen() -> Result<(), Box<dyn std::error::Error>> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed)?;
    let signing_key = SigningKey::from_bytes(&seed);
    println!("private_key_hex {}", encode_hex(&seed));
    println!(
        "public_key_hex  {}",
        encode_hex(signing_key.verifying_key().as_bytes())
    );
    Ok(())
}

fn load_openssh_ed25519_private_key(
    path: &str,
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    parse_openssh_ed25519_private_key(&fs::read_to_string(path)?)
}

fn parse_openssh_ed25519_private_key(
    input: &str,
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let b64: String = input
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let blob = Base64::decode_vec(&b64)?;
    let magic = b"openssh-key-v1\0";
    if !blob.starts_with(magic) {
        return Err("not an OpenSSH private key".into());
    }

    let mut rest = &blob[magic.len()..];
    let (cipher, next) = read_ssh_string(rest)?;
    rest = next;
    let (kdf, next) = read_ssh_string(rest)?;
    rest = next;
    let (_kdf_options, next) = read_ssh_string(rest)?;
    rest = next;

    if cipher != b"none" || kdf != b"none" {
        return Err("encrypted private keys are not supported".into());
    }
    if rest.len() < 4 {
        return Err("missing key count".into());
    }
    let key_count = u32::from_be_bytes(rest[..4].try_into().unwrap());
    rest = &rest[4..];
    if key_count != 1 {
        return Err("expected one private key".into());
    }

    let (_public_blob, next) = read_ssh_string(rest)?;
    rest = next;
    let (private_blob, _next) = read_ssh_string(rest)?;
    parse_ed25519_private_blob(private_blob)
}

fn parse_ed25519_private_blob(
    private_blob: &[u8],
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    if private_blob.len() < 8 {
        return Err("short private key body".into());
    }
    let check1 = u32::from_be_bytes(private_blob[..4].try_into().unwrap());
    let check2 = u32::from_be_bytes(private_blob[4..8].try_into().unwrap());
    if check1 != check2 {
        return Err("private key checkints do not match".into());
    }

    let mut rest = &private_blob[8..];
    let (kind, next) = read_ssh_string(rest)?;
    rest = next;
    if kind != b"ssh-ed25519" {
        return Err("private key must be ssh-ed25519".into());
    }
    let (_public_key, next) = read_ssh_string(rest)?;
    rest = next;
    let (private_key, _next) = read_ssh_string(rest)?;
    if private_key.len() != 64 {
        return Err("ed25519 private key body must be 64 bytes".into());
    }
    let seed: [u8; 32] = private_key[..32].try_into().unwrap();
    Ok(SigningKey::from_bytes(&seed))
}

fn read_ssh_string(
    input: &[u8],
) -> Result<(&[u8], &[u8]), Box<dyn std::error::Error + Send + Sync>> {
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

fn signing_key_from_hex(s: &str) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let bytes: [u8; 32] = decode_hex(s)?
        .try_into()
        .map_err(|_| "private key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex character".into()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_parse_reads_required_fields_and_shell() {
        let config = ClientConfig::parse(
            "
            server = ws://127.0.0.1:8080/bepr/default
            private_key_path = /home/me/.ssh/id_ed25519
            shell = /bin/sh
            ",
        )
        .unwrap();

        assert_eq!(config.server, "ws://127.0.0.1:8080/bepr/default");
        assert_eq!(
            config.private_key,
            PrivateKeyConfig::Path("/home/me/.ssh/id_ed25519".to_string())
        );
        assert_eq!(config.shell, "/bin/sh");
    }

    #[test]
    fn client_config_parse_defaults_shell() {
        let config = ClientConfig::parse(
            "
            server = ws://127.0.0.1:8080/bepr/default
            private_key_path = /home/me/.ssh/id_ed25519
            ",
        )
        .unwrap();

        assert_eq!(config.shell, "/bin/sh");
    }

    #[test]
    fn client_config_parse_rejects_unknown_key() {
        assert!(ClientConfig::parse(
            "
            server = ws://127.0.0.1:8080/bepr/default
            private_key_path = /home/me/.ssh/id_ed25519
            typo = nope
            ",
        )
        .is_err());
    }

    #[test]
    fn client_config_from_args_accepts_positional_hex_key() {
        let config = ClientConfig::from_args(vec![
            "ws://127.0.0.1:8080/bepr/default".to_string(),
            "00".repeat(32),
        ])
        .unwrap();

        assert_eq!(config.server, "ws://127.0.0.1:8080/bepr/default");
        assert_eq!(config.private_key, PrivateKeyConfig::Hex("00".repeat(32)));
        assert_eq!(config.shell, "/bin/sh");
    }

    #[test]
    fn signing_key_from_hex_rejects_wrong_length() {
        assert!(signing_key_from_hex("00").is_err());
    }

    #[test]
    fn decode_hex_round_trips_encoded_bytes() {
        let bytes = [0_u8, 1, 2, 15, 16, 127, 128, 255];
        assert_eq!(decode_hex(&encode_hex(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }
}
