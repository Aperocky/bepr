use std::env;

use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
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
    "usage: bepr server [--config server.conf]\n       bepr client [--config client.conf]\n       bepr connect <client_id>\n       bepr list\n       bepr keygen".to_string()
}

async fn connect(args: Vec<String>) -> Result<(), String> {
    let client_id = parse_connect_args(args)?;
    let mut stream = UnixStream::connect(DEFAULT_OPERATOR_SOCKET)
        .await
        .map_err(|err| err.to_string())?;
    stream
        .write_all(format!("CONNECT {client_id}\n").as_bytes())
        .await
        .map_err(|err| err.to_string())?;

    let response = read_line(&mut stream).await.map_err(|err| err.to_string())?;
    if response != "OK" {
        return Err(response);
    }

    let (mut reader, mut writer) = stream.into_split();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let to_daemon = tokio::spawn(async move {
        let mut buf = [0_u8; 8192];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n]).await?;
            writer.flush().await?;
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
    Ok(())
}

async fn list(args: Vec<String>) -> Result<(), String> {
    parse_list_args(args)?;
    let mut stream = UnixStream::connect(DEFAULT_OPERATOR_SOCKET)
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

fn parse_connect_args(args: Vec<String>) -> Result<String, String> {
    match args.as_slice() {
        [client_id] => Ok(client_id.clone()),
        _ => Err("usage: bepr connect <client_id>".to_string()),
    }
}

fn parse_list_args(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [] => Ok(()),
        _ => Err("usage: bepr list".to_string()),
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
