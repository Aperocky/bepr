use std::{env, sync::Arc, time::Duration};

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

use crate::config::ClientConfig;
use crate::util::log;

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

const CLIENT_PING_INTERVAL_SECS: u64 = 35;

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

    let mut ping_interval = tokio::time::interval(Duration::from_secs(CLIENT_PING_INTERVAL_SECS));
    ping_interval.tick().await; // consume immediate first tick

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
            _ = ping_interval.tick() => {
                ws_tx.send(Message::Ping(vec![])).await?;
            }
        }
    }

    let _ = child.kill().await;
    log(format!("disconnected from {server}"));
    Ok(())
}

