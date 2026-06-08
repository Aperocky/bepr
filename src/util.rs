use std::time::{SystemTime, UNIX_EPOCH};

pub fn log(msg: impl std::fmt::Display) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    eprintln!("[{ts}] {msg}");
}
