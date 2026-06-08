use std::time::{SystemTime, UNIX_EPOCH};

use tokio::{io::AsyncReadExt, net::UnixStream};

pub fn log(msg: impl std::fmt::Display) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    eprintln!("[{}] {msg}", format_utc(secs));
}


fn format_utc(secs: u64) -> String {
    let (mut days, time) = (secs / 86400, secs % 86400);
    let (h, m, s) = (time / 3600, (time % 3600) / 60, time % 60);

    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let month_days: [u64; 12] = [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;

    format!("{year}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub async fn read_line(stream: &mut UnixStream) -> std::io::Result<String> {
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

pub fn read_ssh_string(
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
