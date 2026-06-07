use std::{env, io::IsTerminal, time::Duration};

use tokio::{
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::sleep,
};

use crate::{
    client,
    server::{self, DEFAULT_OPERATOR_SOCKET},
};

pub async fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") => server::run(args[1..].to_vec()).await,
        Some("client") => client::run(args[1..].to_vec()).await,
        Some("connect") => connect(args[1..].to_vec()).await,
        Some("list") => list(args[1..].to_vec()).await,
        Some("keygen") => client::keygen().map_err(|err| err.to_string()),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: bepr server [--config server.conf]\n       bepr client [--config client.conf]\n       bepr connect [--socket path] <client_id>\n       bepr list [--socket path]\n       bepr keygen".to_string()
}

async fn connect(args: Vec<String>) -> Result<(), String> {
    let args = parse_connect_args(args)?;
    let mut stream = UnixStream::connect(&args.socket)
        .await
        .map_err(|err| err.to_string())?;
    stream
        .write_all(format!("CONNECT {}\n", args.client_id).as_bytes())
        .await
        .map_err(|err| err.to_string())?;

    let response = read_line(&mut stream).await.map_err(|err| err.to_string())?;
    if response != "OK" {
        return Err(response);
    }

    let (mut reader, mut writer) = stream.into_split();
    let stdin_is_terminal = std::io::stdin().is_terminal();
    let mut stdout = io::stdout();

    let to_daemon = tokio::spawn(async move {
        if stdin_is_terminal {
            let mut stdin = io::BufReader::new(io::stdin());
            let mut stderr = io::stderr();
            let mut line = Vec::new();
            loop {
                stderr.write_all(b"> ").await?;
                stderr.flush().await?;
                line.clear();
                let n = stdin.read_until(b'\n', &mut line).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&line).await?;
                writer.flush().await?;
                sleep(Duration::from_millis(100)).await;
            }
        } else {
            let mut stdin = io::stdin();
            let mut buf = [0_u8; 8192];
            loop {
                let n = stdin.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n]).await?;
                writer.flush().await?;
            }
        }
        Ok::<_, std::io::Error>(())
    });

    let mut buf = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buf).await.map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n]).await.map_err(|err| err.to_string())?;
        stdout.flush().await.map_err(|err| err.to_string())?;
    }
    to_daemon.abort();
    std::process::exit(0);
}

async fn list(args: Vec<String>) -> Result<(), String> {
    let args = parse_list_args(args)?;
    let mut stream = UnixStream::connect(&args.socket)
        .await
        .map_err(|err| err.to_string())?;
    stream
        .write_all(b"LIST\n")
        .await
        .map_err(|err| err.to_string())?;

    let response = read_line(&mut stream).await.map_err(|err| err.to_string())?;
    if response != "OK" {
        return Err(response);
    }

    let mut stdout = io::stdout();
    let mut buf = [0_u8; 8192];
    loop {
        let n = stream.read(&mut buf).await.map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n]).await.map_err(|err| err.to_string())?;
    }
    stdout.flush().await.map_err(|err| err.to_string())?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ConnectArgs {
    client_id: String,
    socket: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ListArgs {
    socket: String,
}

fn parse_connect_args(args: Vec<String>) -> Result<ConnectArgs, String> {
    match args.as_slice() {
        [client_id] => Ok(ConnectArgs {
            client_id: client_id.clone(),
            socket: DEFAULT_OPERATOR_SOCKET.to_string(),
        }),
        [flag, socket, client_id] if flag == "--socket" => Ok(ConnectArgs {
            client_id: client_id.clone(),
            socket: socket.clone(),
        }),
        _ => Err("usage: bepr connect [--socket path] <client_id>".to_string()),
    }
}

fn parse_list_args(args: Vec<String>) -> Result<ListArgs, String> {
    match args.as_slice() {
        [] => Ok(ListArgs {
            socket: DEFAULT_OPERATOR_SOCKET.to_string(),
        }),
        [flag, socket] if flag == "--socket" => Ok(ListArgs {
            socket: socket.clone(),
        }),
        _ => Err("usage: bepr list [--socket path]".to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_args_accepts_client_id() {
        assert_eq!(
            parse_connect_args(vec!["laptop".to_string()]).unwrap(),
            ConnectArgs {
                client_id: "laptop".to_string(),
                socket: DEFAULT_OPERATOR_SOCKET.to_string(),
            }
        );
    }

    #[test]
    fn parse_connect_args_accepts_socket_flag() {
        assert_eq!(
            parse_connect_args(vec![
                "--socket".to_string(),
                "/tmp/bepr-remote.sock".to_string(),
                "laptop".to_string(),
            ])
            .unwrap(),
            ConnectArgs {
                client_id: "laptop".to_string(),
                socket: "/tmp/bepr-remote.sock".to_string(),
            }
        );
    }

    #[test]
    fn parse_connect_args_rejects_config_flag() {
        assert!(parse_connect_args(vec![
            "laptop".to_string(),
            "--config".to_string(),
            "server.conf".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn parse_list_args_accepts_no_args() {
        assert_eq!(
            parse_list_args(Vec::new()).unwrap(),
            ListArgs {
                socket: DEFAULT_OPERATOR_SOCKET.to_string(),
            }
        );
    }

    #[test]
    fn parse_list_args_accepts_socket_flag() {
        assert_eq!(
            parse_list_args(vec![
                "--socket".to_string(),
                "/tmp/bepr-remote.sock".to_string(),
            ])
            .unwrap(),
            ListArgs {
                socket: "/tmp/bepr-remote.sock".to_string(),
            }
        );
    }

    #[test]
    fn parse_list_args_rejects_extra_args() {
        assert!(parse_list_args(vec!["--config".to_string(), "server.conf".to_string()]).is_err());
    }
}
