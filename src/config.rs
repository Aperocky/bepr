use std::{collections::HashMap, env, fs, path::PathBuf};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::util::read_ssh_string;

pub const DEFAULT_SERVER_CONFIG: &str = "/etc/bepr/server.conf";
pub const DEFAULT_BIND: &str = "0.0.0.0:443";
pub const DEFAULT_CLIENT_CONFIG: &str = "/etc/bepr/client.conf";

// ── ServerConfig ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub struct ServerConfig {
    pub bind: String,
    pub key_dir: String,
    pub user_key_dir: Option<String>,
    pub tls_cert: String,
    pub tls_key: String,
}

impl ServerConfig {
    pub fn from_args(args: Vec<String>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match args.as_slice() {
            [] => Self::from_file(DEFAULT_SERVER_CONFIG),
            [flag, path] if flag == "--config" || flag == "-c" => Self::from_file(path),
            _ => Err("usage: bepr server [--config server.conf]".into()),
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::parse(&fs::read_to_string(path)?)
    }

    fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut bind = None;
        let mut key_dir = None;
        let mut user_key_dir = None;
        let mut tls_cert = None;
        let mut tls_key = None;

        for (idx, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("config:{} expected key = value", idx + 1).into());
            };
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("config:{} empty value for {key}", idx + 1).into());
            }
            match key {
                "bind"         => bind         = Some(value.to_string()),
                "key_dir"      => key_dir      = Some(value.to_string()),
                "user_key_dir" => user_key_dir = Some(value.to_string()),
                "tls_cert"     => tls_cert     = Some(value.to_string()),
                "tls_key"      => tls_key      = Some(value.to_string()),
                _ => return Err(format!("config:{} unknown key {key}", idx + 1).into()),
            }
        }

        Ok(Self {
            bind: bind.unwrap_or_else(|| DEFAULT_BIND.to_string()),
            key_dir: key_dir.ok_or("config missing key_dir")?,
            user_key_dir,
            tls_cert: tls_cert.ok_or("config missing tls_cert")?,
            tls_key: tls_key.ok_or("config missing tls_key")?,
        })
    }

    pub fn load_public_keys(&self) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error + Send + Sync>> {
        load_key_dir(&self.key_dir)
    }

    pub fn load_user_keys(&self) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error + Send + Sync>> {
        match self.user_key_dir.as_deref() {
            Some(dir) => load_key_dir(dir),
            None => Ok(HashMap::new()),
        }
    }
}

// ── ClientConfig ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub struct ClientConfig {
    pub server: String,
    pub private_key: PrivateKeyConfig,
    pub shell: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PrivateKeyConfig {
    Path(String),
    Hex(String),
}

impl ClientConfig {
    pub fn from_args(args: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        match args.as_slice() {
            [] => Self::from_file(DEFAULT_CLIENT_CONFIG),
            [flag, path] if flag == "--config" || flag == "-c" => Self::from_file(path),
            [server, private_key] => {
                if !server.starts_with("wss://") {
                    return Err("server URL must use wss:// (plaintext ws:// is not allowed)".into());
                }
                Ok(Self { server: server.clone(), private_key: PrivateKeyConfig::Hex(private_key.clone()), shell: default_shell() })
            }
            [server, private_key, shell] => {
                if !server.starts_with("wss://") {
                    return Err("server URL must use wss:// (plaintext ws:// is not allowed)".into());
                }
                Ok(Self { server: server.clone(), private_key: PrivateKeyConfig::Hex(private_key.clone()), shell: shell.clone() })
            }
            _ => Err("invalid client arguments".into()),
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::parse(&fs::read_to_string(path)?)
    }

    pub fn load_signing_key(&self) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
        match &self.private_key {
            PrivateKeyConfig::Path(path) => load_openssh_ed25519_private_key(path),
            PrivateKeyConfig::Hex(hex)   => signing_key_from_hex(hex),
        }
    }

    fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut server = None;
        let mut private_key_path = None;
        let mut shell = None;

        for (idx, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("config:{} expected key = value", idx + 1).into());
            };
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("config:{} empty value for {key}", idx + 1).into());
            }
            match key {
                "server"           => server           = Some(value.to_string()),
                "private_key_path" => private_key_path = Some(value.to_string()),
                "shell"            => shell             = Some(value.to_string()),
                _ => return Err(format!("config:{} unknown key {key}", idx + 1).into()),
            }
        }

        let server = server.ok_or("config missing server")?;
        if !server.starts_with("wss://") {
            return Err("server URL must use wss:// (plaintext ws:// is not allowed)".into());
        }
        Ok(Self {
            server,
            private_key: PrivateKeyConfig::Path(private_key_path.ok_or("config missing private_key_path")?),
            shell: shell.unwrap_or_else(default_shell),
        })
    }
}

fn default_shell() -> String {
    "/bin/sh".to_string()
}

// ── UserConfig ────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub struct UserConfig {
    pub server: String,
    pub private_key_path: String,
}

impl UserConfig {
    /// Tries ~/.config/bepr/user.conf then /etc/bepr/user.conf.
    /// Returns Ok(None) if neither file exists.
    pub fn load_default() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if let Some(home) = env::var_os("HOME") {
            let path = PathBuf::from(home).join(".config/bepr/user.conf");
            if path.exists() {
                return Self::from_file(path.to_str().ok_or("non-utf8 home path")?).map(Some);
            }
        }
        let system = "/etc/bepr/user.conf";
        if PathBuf::from(system).exists() {
            return Self::from_file(system).map(Some);
        }
        Ok(None)
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::parse(&fs::read_to_string(path)?)
    }

    fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut server = None;
        let mut private_key_path = None;

        for (idx, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("config:{} expected key = value", idx + 1).into());
            };
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("config:{} empty value for {key}", idx + 1).into());
            }
            match key {
                "server"           => server           = Some(value.to_string()),
                "private_key_path" => private_key_path = Some(value.to_string()),
                _ => return Err(format!("config:{} unknown key {key}", idx + 1).into()),
            }
        }

        let server = server.ok_or("config missing server")?;
        if !server.starts_with("wss://") {
            return Err("user config server must use wss://".into());
        }
        Ok(Self {
            server,
            private_key_path: private_key_path.ok_or("config missing private_key_path")?,
        })
    }
}

// ── Public key helpers ────────────────────────────────────────────────────────

pub fn load_key_dir(dir: &str) -> Result<HashMap<String, VerifyingKey>, Box<dyn std::error::Error + Send + Sync>> {
    let mut keys = HashMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("pub") { continue; }
        let id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| format!("invalid public key filename {}", path.display()))?;
        let path = path.to_str().ok_or("public key path is not utf-8")?;
        keys.insert(id.to_string(), load_public_key(path)?);
    }
    Ok(keys)
}

fn load_public_key(path: &str) -> Result<VerifyingKey, Box<dyn std::error::Error + Send + Sync>> {
    parse_openssh_ed25519_public_key(&fs::read_to_string(path)?)
}

pub fn parse_openssh_ed25519_public_key(
    input: &str,
) -> Result<VerifyingKey, Box<dyn std::error::Error + Send + Sync>> {
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
    let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| "ed25519 public key must be 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}

// ── Private key helpers ───────────────────────────────────────────────────────

pub fn load_openssh_ed25519_private_key(
    path: &str,
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    parse_openssh_ed25519_private_key(&fs::read_to_string(path)?)
}

fn parse_openssh_ed25519_private_key(
    input: &str,
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let b64: String = input.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    let blob = Base64::decode_vec(&b64)?;
    let magic = b"openssh-key-v1\0";
    if !blob.starts_with(magic) {
        return Err("not an OpenSSH private key".into());
    }
    let mut rest = &blob[magic.len()..];
    let (cipher, next) = read_ssh_string(rest)?; rest = next;
    let (kdf,    next) = read_ssh_string(rest)?; rest = next;
    let (_,      next) = read_ssh_string(rest)?; rest = next;
    if cipher != b"none" || kdf != b"none" {
        return Err("encrypted private keys are not supported".into());
    }
    if rest.len() < 4 { return Err("missing key count".into()); }
    let key_count = u32::from_be_bytes(rest[..4].try_into().unwrap());
    rest = &rest[4..];
    if key_count != 1 { return Err("expected one private key".into()); }
    let (_, next) = read_ssh_string(rest)?; rest = next;
    let (private_blob, _) = read_ssh_string(rest)?;
    parse_ed25519_private_blob(private_blob)
}

fn parse_ed25519_private_blob(
    blob: &[u8],
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    if blob.len() < 8 { return Err("short private key body".into()); }
    let check1 = u32::from_be_bytes(blob[..4].try_into().unwrap());
    let check2 = u32::from_be_bytes(blob[4..8].try_into().unwrap());
    if check1 != check2 { return Err("private key checkints do not match".into()); }
    let mut rest = &blob[8..];
    let (kind, next) = read_ssh_string(rest)?; rest = next;
    if kind != b"ssh-ed25519" { return Err("private key must be ssh-ed25519".into()); }
    let (_, next) = read_ssh_string(rest)?; rest = next;
    let (private_key, _) = read_ssh_string(rest)?;
    if private_key.len() != 64 { return Err("ed25519 private key body must be 64 bytes".into()); }
    Ok(SigningKey::from_bytes(&private_key[..32].try_into().unwrap()))
}

fn signing_key_from_hex(s: &str) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let bytes: [u8; 32] = decode_hex(s)?.try_into().map_err(|_| "private key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if s.len() % 2 != 0 { return Err("hex string has odd length".into()); }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
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
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("{name}-{}-{nanos}", std::process::id()))
    }

    // ── ServerConfig ──────────────────────────────────────────────────────────

    #[test]
    fn server_config_parse_reads_all_fields() {
        let config = ServerConfig::parse(
            "bind = 0.0.0.0:8080\nkey_dir = /etc/bepr/keys\ntls_cert = /etc/bepr/tls/cert.pem\ntls_key = /etc/bepr/tls/key.pem\n",
        ).unwrap();
        assert_eq!(config.bind, "0.0.0.0:8080");
        assert_eq!(config.key_dir, "/etc/bepr/keys");
        assert_eq!(config.tls_cert, "/etc/bepr/tls/cert.pem");
        assert_eq!(config.tls_key, "/etc/bepr/tls/key.pem");
    }

    #[test]
    fn server_config_parse_defaults_bind() {
        let config = ServerConfig::parse(
            "key_dir = /etc/bepr/keys\ntls_cert = /etc/bepr/tls/cert.pem\ntls_key = /etc/bepr/tls/key.pem\n"
        ).unwrap();
        assert_eq!(config.bind, DEFAULT_BIND);
    }

    #[test]
    fn server_config_parse_requires_key_dir() {
        assert!(ServerConfig::parse("bind = 127.0.0.1:8080\ntls_cert = /etc/bepr/tls/cert.pem\ntls_key = /etc/bepr/tls/key.pem\n").is_err());
    }

    #[test]
    fn server_config_parse_requires_tls_cert() {
        assert!(ServerConfig::parse("bind = 127.0.0.1:8080\nkey_dir = /etc/bepr/keys\ntls_key = /etc/bepr/tls/key.pem\n").is_err());
    }

    #[test]
    fn server_config_parse_requires_tls_key() {
        assert!(ServerConfig::parse("bind = 127.0.0.1:8080\nkey_dir = /etc/bepr/keys\ntls_cert = /etc/bepr/tls/cert.pem\n").is_err());
    }

    #[test]
    fn server_config_parse_rejects_unknown_key() {
        assert!(ServerConfig::parse(
            "bind = 127.0.0.1:8080\nkey_dir = /etc/bepr/keys\ntls_cert = /etc/bepr/tls/cert.pem\ntls_key = /etc/bepr/tls/key.pem\noperator_socket = /tmp/other.sock\n"
        ).is_err());
    }

    #[test]
    fn parse_public_key_reads_openssh_ed25519() {
        let key = parse_openssh_ed25519_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI\n",
        ).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn parse_public_key_rejects_non_ed25519_kind() {
        assert!(parse_openssh_ed25519_public_key("ssh-rsa AAAA").is_err());
    }

    #[test]
    fn load_public_keys_from_key_dir() {
        let dir = temp_dir("bepr-key-dir");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("laptop.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPPixtDFSIPO+YfoD8qk2AQFNAfh7NuizV5cdQ0ii4CI\n",
        ).unwrap();
        fs::write(dir.join("ignored.txt"), "nope").unwrap();
        let keys = load_key_dir(dir.to_str().unwrap()).unwrap();
        assert!(keys.contains_key("laptop"));
        assert!(!keys.contains_key("ignored"));
        let _ = fs::remove_dir_all(dir);
    }

    // ── ClientConfig ──────────────────────────────────────────────────────────

    #[test]
    fn client_config_parse_reads_required_fields_and_shell() {
        let config = ClientConfig::parse(
            "server = wss://127.0.0.1:8080/bepr/default\nprivate_key_path = /home/me/.ssh/id_ed25519\nshell = /bin/sh\n",
        ).unwrap();
        assert_eq!(config.server, "wss://127.0.0.1:8080/bepr/default");
        assert_eq!(config.private_key, PrivateKeyConfig::Path("/home/me/.ssh/id_ed25519".to_string()));
        assert_eq!(config.shell, "/bin/sh");
    }

    #[test]
    fn client_config_parse_defaults_shell() {
        let config = ClientConfig::parse(
            "server = wss://127.0.0.1:8080/bepr/default\nprivate_key_path = /home/me/.ssh/id_ed25519\n",
        ).unwrap();
        assert_eq!(config.shell, "/bin/sh");
    }

    #[test]
    fn client_config_parse_rejects_unknown_key() {
        assert!(ClientConfig::parse(
            "server = wss://127.0.0.1:8080/bepr/default\nprivate_key_path = /home/me/.ssh/id_ed25519\ntypo = nope\n",
        ).is_err());
    }

    #[test]
    fn client_config_parse_rejects_plaintext_ws_url() {
        assert!(ClientConfig::parse(
            "server = ws://127.0.0.1:8080/bepr/default\nprivate_key_path = /home/me/.ssh/id_ed25519\n",
        ).is_err());
    }

    #[test]
    fn client_config_from_args_accepts_positional_hex_key() {
        let config = ClientConfig::from_args(vec![
            "wss://127.0.0.1:8080/bepr/default".to_string(),
            "00".repeat(32),
        ]).unwrap();
        assert_eq!(config.server, "wss://127.0.0.1:8080/bepr/default");
        assert_eq!(config.private_key, PrivateKeyConfig::Hex("00".repeat(32)));
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

    // ── UserConfig ────────────────────────────────────────────────────────────

    #[test]
    fn user_config_parse_reads_fields() {
        let config = UserConfig::parse(
            "server = wss://myserver.com/bepr/user/me\nprivate_key_path = /etc/bepr/user_keys/me\n",
        ).unwrap();
        assert_eq!(config.server, "wss://myserver.com/bepr/user/me");
        assert_eq!(config.private_key_path, "/etc/bepr/user_keys/me");
    }

    #[test]
    fn user_config_parse_rejects_plaintext_ws_url() {
        assert!(UserConfig::parse(
            "server = ws://myserver.com/bepr/user/me\nprivate_key_path = /etc/bepr/user_keys/me\n",
        ).is_err());
    }

    #[test]
    fn user_config_parse_requires_server() {
        assert!(UserConfig::parse("private_key_path = /etc/bepr/user_keys/me\n").is_err());
    }

    #[test]
    fn user_config_parse_requires_private_key_path() {
        assert!(UserConfig::parse("server = wss://myserver.com/bepr/user/me\n").is_err());
    }
}
