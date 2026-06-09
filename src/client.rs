use std::{env, fs, sync::Arc, time::Duration};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use rustls::{
    ClientConfig as RustlsClientConfig,
    DigitallySignedStruct,
    Error as RustlsError,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};
use tokio_tungstenite::{connect_async, connect_async_tls_with_config, tungstenite::Message};

use crate::util::{log, read_ssh_string};

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

const DEFAULT_CLIENT_CONFIG: &str = "/etc/bepr/client.conf";

pub async fn connect_authenticated(
    url: &str,
    key: &SigningKey,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Box<dyn std::error::Error + Send + Sync>> {
    let (mut ws, _) = if env::var("BEPR_INSECURE_SKIP_TLS_VERIFY").is_ok() {
        let config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        connect_async_tls_with_config(
            url,
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))),
        )
        .await?
    } else {
        connect_async(url).await?
    };

    let Some(msg) = ws.next().await else {
        return Err("server disconnected before challenge".into());
    };
    let challenge = match msg? {
        Message::Binary(bytes) => bytes,
        _ => return Err("expected binary challenge".into()),
    };
    ws.send(Message::Binary(key.sign(&challenge).to_bytes().to_vec())).await?;

    Ok(ws)
}

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let config = ClientConfig::from_args(args).map_err(|err| err.to_string())?;
    let key = config.load_signing_key().map_err(|err| err.to_string())?;

    loop {
        if let Err(err) = run_once(&config.server, &key, &config.shell).await {
            log(format!("disconnected: {err}"));
        }
        sleep(Duration::from_secs(10)).await;
    }
}

async fn run_once(
    server: &str,
    key: &SigningKey,
    shell: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = connect_authenticated(server, key).await?;
    log(format!("connected to {server}"));
    let (pty, pts) = pty_process::open()?;
    let mut child = pty_process::Command::new(shell)
        .env("TERM", "xterm")
        .spawn(pts)?;
    let (mut pty_read, mut pty_write) = pty.into_split();
    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut buf = [0_u8; 8192];

    loop {
        tokio::select! {
            status = child.wait() => {
                status?;
                ws_tx.send(Message::Close(None)).await?;
                break;
            }
            read = pty_read.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                ws_tx.send(Message::Binary(buf[..n].to_vec())).await?;
            }
            msg = ws_rx.next() => {
                let Some(msg) = msg else {
                    break;
                };
                match msg? {
                    Message::Binary(bytes) => pty_write.write_all(&bytes).await?,
                    Message::Text(text) => pty_write.write_all(text.as_bytes()).await?,
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    let _ = child.kill().await;
    log(format!("disconnected from {server}"));
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
            [server, private_key] => {
                if !server.starts_with("wss://") {
                    return Err("server URL must use wss:// (plaintext ws:// is not allowed)".into());
                }
                Ok(Self {
                    server: server.clone(),
                    private_key: PrivateKeyConfig::Hex(private_key.clone()),
                    shell: default_shell(),
                })
            }
            [server, private_key, shell] => {
                if !server.starts_with("wss://") {
                    return Err("server URL must use wss:// (plaintext ws:// is not allowed)".into());
                }
                Ok(Self {
                    server: server.clone(),
                    private_key: PrivateKeyConfig::Hex(private_key.clone()),
                    shell: shell.clone(),
                })
            }
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

        let server = server.ok_or("config missing server")?;
        if !server.starts_with("wss://") {
            return Err("server URL must use wss:// (plaintext ws:// is not allowed)".into());
        }
        Ok(Self {
            server,
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

pub fn load_openssh_ed25519_private_key(
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

#[cfg(test)]
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
            server = wss://127.0.0.1:8080/bepr/default
            private_key_path = /home/me/.ssh/id_ed25519
            shell = /bin/sh
            ",
        )
        .unwrap();

        assert_eq!(config.server, "wss://127.0.0.1:8080/bepr/default");
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
            server = wss://127.0.0.1:8080/bepr/default
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
            server = wss://127.0.0.1:8080/bepr/default
            private_key_path = /home/me/.ssh/id_ed25519
            typo = nope
            ",
        )
        .is_err());
    }

    #[test]
    fn client_config_parse_rejects_plaintext_ws_url() {
        assert!(ClientConfig::parse(
            "
            server = ws://127.0.0.1:8080/bepr/default
            private_key_path = /home/me/.ssh/id_ed25519
            ",
        )
        .is_err());
    }

    #[test]
    fn client_config_from_args_accepts_positional_hex_key() {
        let config = ClientConfig::from_args(vec![
            "wss://127.0.0.1:8080/bepr/default".to_string(),
            "00".repeat(32),
        ])
        .unwrap();

        assert_eq!(config.server, "wss://127.0.0.1:8080/bepr/default");
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
