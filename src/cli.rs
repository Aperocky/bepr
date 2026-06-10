use std::{env, io::IsTerminal, os::fd::AsFd};

use futures_util::{SinkExt, StreamExt};
use rustix::termios::{tcgetattr, tcsetattr, OptionalActions, Termios};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::mpsc,
};
use tokio_tungstenite::tungstenite::Message;

use crate::{
    client,
    config::{load_openssh_ed25519_private_key, UserConfig},
    server::{self, DEFAULT_OPERATOR_SOCKET},
    util::read_line,
};

pub async fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("{}", version());
            Ok(())
        }
        Some("server")  => server::run(args[1..].to_vec()).await,
        Some("client")  => client::run(args[1..].to_vec()).await,
        Some("connect") => connect(args[1..].to_vec()).await,
        Some("list")    => list(args[1..].to_vec()).await,
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: bepr server [--config server.conf]\n       bepr client [--config client.conf]\n       bepr connect [--socket path|wss://url] [--key key_path] <client_id>\n       bepr list [--socket path|wss://url] [--key key_path]".to_string()
}

fn version() -> String {
    format!("bepr {}", env!("CARGO_PKG_VERSION"))
}

async fn connect(args: Vec<String>) -> Result<(), String> {
    let mut args = parse_connect_args(args)?;
    if args.socket.is_none() || args.key_path.is_none() {
        if let Ok(Some(user_cfg)) = UserConfig::load_default() {
            args.socket.get_or_insert(user_cfg.server);
            args.key_path.get_or_insert(user_cfg.private_key_path);
        }
    }
    let socket = args.socket.unwrap_or_else(|| DEFAULT_OPERATOR_SOCKET.to_string());
    if socket.starts_with("wss://") {
        let key_path = args.key_path.as_deref().ok_or("--key required for wss:// socket")?;
        let key = load_openssh_ed25519_private_key(key_path).map_err(|e| e.to_string())?;
        let ws = client::connect_authenticated(&socket, &key).await.map_err(|e| e.to_string())?;
        let (mut ws_tx, mut ws_rx) = ws.split();

        ws_tx.send(Message::Binary(format!("CONNECT {}", args.client_id).into_bytes()))
            .await.map_err(|e| e.to_string())?;

        let reply = match ws_rx.next().await {
            Some(Ok(Message::Binary(b))) => b,
            Some(Err(e)) => return Err(e.to_string()),
            _ => return Err("server disconnected".into()),
        };
        if reply != b"OK\n" {
            return Err(String::from_utf8_lossy(&reply).trim_end().to_string());
        }

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(8);
        let stdin_is_terminal = std::io::stdin().is_terminal();
        tokio::spawn(async move {
            let mut stdin = io::stdin();
            let mut buf = [0_u8; 8192];
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let bytes = if stdin_is_terminal { buf[..n].to_vec() } else { lf_to_cr(&buf[..n]) };
                if stdin_tx.send(bytes).await.is_err() { break; }
            }
        });

        let mut raw_terminal = RawTerminal::enable_if_terminal().map_err(|e| e.to_string())?;
        let mut stdout = io::stdout();
        loop {
            tokio::select! {
                bytes = stdin_rx.recv() => {
                    let Some(bytes) = bytes else { break; };
                    ws_tx.send(Message::Binary(bytes)).await.map_err(|e| e.to_string())?;
                }
                msg = ws_rx.next() => {
                    match msg {
                        Some(Ok(Message::Binary(b))) => {
                            stdout.write_all(&b).await.map_err(|e| e.to_string())?;
                            stdout.flush().await.map_err(|e| e.to_string())?;
                        }
                        Some(Ok(Message::Text(t))) => {
                            stdout.write_all(t.as_bytes()).await.map_err(|e| e.to_string())?;
                            stdout.flush().await.map_err(|e| e.to_string())?;
                        }
                        Some(Ok(Message::Ping(d))) => {
                            ws_tx.send(Message::Pong(d)).await.map_err(|e| e.to_string())?;
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Ok(_)) => {}
                        Some(Err(e)) => { eprintln!("{e}"); break; }
                    }
                }
            }
        }
        raw_terminal.restore().map_err(|e| format!("restore terminal: {e}"))?;
    } else {
        let mut stream = UnixStream::connect(&socket).await.map_err(|e| e.to_string())?;
        stream.write_all(format!("CONNECT {}\n", args.client_id).as_bytes())
            .await.map_err(|e| e.to_string())?;

        let response = read_line(&mut stream).await.map_err(|e| e.to_string())?;
        if response != "OK" { return Err(response); }

        let (mut reader, mut writer) = stream.into_split();
        let stdin_is_terminal = std::io::stdin().is_terminal();
        let mut raw_terminal = RawTerminal::enable_if_terminal().map_err(|e| e.to_string())?;
        let mut stdout = io::stdout();

        let to_daemon = tokio::spawn(async move {
            let mut stdin = io::stdin();
            let mut buf = [0_u8; 8192];
            loop {
                let n = stdin.read(&mut buf).await?;
                if n == 0 { break; }
                let bytes = if stdin_is_terminal { buf[..n].to_vec() } else { lf_to_cr(&buf[..n]) };
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
            Ok::<_, std::io::Error>(())
        });

        let mut buf = [0_u8; 8192];
        loop {
            let n = reader.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 { break; }
            stdout.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
            stdout.flush().await.map_err(|e| e.to_string())?;
        }
        raw_terminal.restore().map_err(|e| format!("restore terminal: {e}"))?;
        to_daemon.abort();
    }
    std::process::exit(0);
}

async fn list(args: Vec<String>) -> Result<(), String> {
    let mut args = parse_list_args(args)?;
    if args.socket.is_none() || args.key_path.is_none() {
        if let Ok(Some(user_cfg)) = UserConfig::load_default() {
            args.socket.get_or_insert(user_cfg.server);
            args.key_path.get_or_insert(user_cfg.private_key_path);
        }
    }
    let socket = args.socket.unwrap_or_else(|| DEFAULT_OPERATOR_SOCKET.to_string());
    if socket.starts_with("wss://") {
        let key_path = args.key_path.as_deref().ok_or("--key required for wss:// socket")?;
        let key = load_openssh_ed25519_private_key(key_path).map_err(|e| e.to_string())?;
        let mut ws = client::connect_authenticated(&socket, &key).await.map_err(|e| e.to_string())?;

        ws.send(Message::Binary(b"LIST".to_vec())).await.map_err(|e| e.to_string())?;

        let body = match ws.next().await {
            Some(Ok(Message::Binary(b))) => b,
            Some(Err(e)) => return Err(e.to_string()),
            _ => return Err("server disconnected".into()),
        };
        let body = body.strip_prefix(b"OK\n").ok_or("unexpected response")?;
        let text = std::str::from_utf8(body).map_err(|e| e.to_string())?;
        print_list(text);
    } else {
        let mut stream = UnixStream::connect(&socket).await.map_err(|e| e.to_string())?;
        stream.write_all(b"LIST\n").await.map_err(|e| e.to_string())?;

        let response = read_line(&mut stream).await.map_err(|e| e.to_string())?;
        if response != "OK" { return Err(response); }

        let mut buf = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 { break; }
            buf.extend_from_slice(&chunk[..n]);
        }
        let text = std::str::from_utf8(&buf).map_err(|e| e.to_string())?;
        print_list(text);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ConnectArgs {
    client_id: String,
    socket: Option<String>,
    key_path: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct ListArgs {
    socket: Option<String>,
    key_path: Option<String>,
}

fn print_list(text: &str) {
    let entries: Vec<(&str, &str, &str)> = text
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            Some((parts.next()?, parts.next()?, parts.next()?))
        })
        .collect();
    let max_id_len = entries.iter().map(|(id, _, _)| id.len()).max().unwrap_or(0);
    let max_type_len = entries.iter().map(|(_, t, _)| t.len()).max().unwrap_or(0);
    for (id, kind, state) in entries {
        println!("{:<id_w$}    {:<type_w$}    {}", id, kind, state, id_w = max_id_len, type_w = max_type_len);
    }
}

fn parse_connect_args(args: Vec<String>) -> Result<ConnectArgs, String> {
    let usage = "usage: bepr connect [--socket path|wss://url] [--key key_path] <client_id>";
    let mut socket = None;
    let mut key_path = None;
    let mut client_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => { i += 1; socket   = Some(args.get(i).ok_or(usage)?.clone()); }
            "--key"    => { i += 1; key_path = Some(args.get(i).ok_or(usage)?.clone()); }
            arg if !arg.starts_with('-') => { client_id = Some(arg.to_string()); }
            arg => return Err(format!("unknown flag {arg}")),
        }
        i += 1;
    }
    Ok(ConnectArgs { client_id: client_id.ok_or(usage)?, socket, key_path })
}

fn parse_list_args(args: Vec<String>) -> Result<ListArgs, String> {
    let usage = "usage: bepr list [--socket path|wss://url] [--key key_path]";
    let mut socket = None;
    let mut key_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => { i += 1; socket   = Some(args.get(i).ok_or(usage)?.clone()); }
            "--key"    => { i += 1; key_path = Some(args.get(i).ok_or(usage)?.clone()); }
            arg => return Err(format!("unknown flag {arg}")),
        }
        i += 1;
    }
    Ok(ListArgs { socket, key_path })
}

fn lf_to_cr(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| if *b == b'\n' { b'\r' } else { *b }).collect()
}

struct RawTerminal {
    original: Option<Termios>,
}

impl RawTerminal {
    fn enable_if_terminal() -> rustix::io::Result<Self> {
        let stdin = std::io::stdin();
        if !stdin.is_terminal() {
            return Ok(Self { original: None });
        }
        let original = tcgetattr(stdin.as_fd())?;
        let mut raw = original.clone();
        raw.make_raw();
        tcsetattr(stdin.as_fd(), OptionalActions::Now, &raw)?;
        Ok(Self { original: Some(original) })
    }

    fn restore(&mut self) -> rustix::io::Result<()> {
        if let Some(original) = self.original.take() {
            tcsetattr(std::io::stdin().as_fd(), OptionalActions::Now, &original)?;
        }
        Ok(())
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_reports_package_version() {
        assert_eq!(version(), format!("bepr {}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn parse_connect_args_accepts_client_id() {
        let args = parse_connect_args(vec!["laptop".to_string()]).unwrap();
        assert_eq!(args.client_id, "laptop");
        assert_eq!(args.socket, None);
        assert_eq!(args.key_path, None);
    }

    #[test]
    fn parse_connect_args_accepts_socket_flag() {
        let args = parse_connect_args(vec![
            "--socket".to_string(), "/tmp/bepr.sock".to_string(), "laptop".to_string(),
        ]).unwrap();
        assert_eq!(args.client_id, "laptop");
        assert_eq!(args.socket.as_deref(), Some("/tmp/bepr.sock"));
    }

    #[test]
    fn parse_connect_args_accepts_wss_socket_with_key() {
        let args = parse_connect_args(vec![
            "--socket".to_string(), "wss://host/bepr/user/me".to_string(),
            "--key".to_string(), "/etc/bepr/keys/me".to_string(),
            "pi".to_string(),
        ]).unwrap();
        assert_eq!(args.socket.as_deref(), Some("wss://host/bepr/user/me"));
        assert_eq!(args.key_path.as_deref(), Some("/etc/bepr/keys/me"));
        assert_eq!(args.client_id, "pi");
    }

    #[test]
    fn parse_connect_args_rejects_missing_client_id() {
        assert!(parse_connect_args(vec![]).is_err());
    }

    #[test]
    fn parse_list_args_accepts_no_args() {
        let args = parse_list_args(vec![]).unwrap();
        assert_eq!(args.socket, None);
        assert_eq!(args.key_path, None);
    }

    #[test]
    fn parse_list_args_accepts_wss_socket_with_key() {
        let args = parse_list_args(vec![
            "--socket".to_string(), "wss://host/bepr/user/me".to_string(),
            "--key".to_string(), "/etc/bepr/keys/me".to_string(),
        ]).unwrap();
        assert_eq!(args.socket.as_deref(), Some("wss://host/bepr/user/me"));
        assert_eq!(args.key_path.as_deref(), Some("/etc/bepr/keys/me"));
    }

    #[test]
    fn parse_list_args_rejects_unknown_flag() {
        assert!(parse_list_args(vec!["--config".to_string(), "x".to_string()]).is_err());
    }

    #[test]
    fn lf_to_cr_translates_piped_newlines_for_pty_input() {
        assert_eq!(lf_to_cr(b"ls\nexit\n"), b"ls\rexit\r");
    }
}
