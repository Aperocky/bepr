use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn authenticated_client_pipes_shell_output_to_server() {
    build_bins();

    let port = free_port();
    let private_key_path = temp_file("bepr-integ-id-ed25519");
    generate_ed25519_key(&private_key_path);
    let public_key_path = PathBuf::from(format!("{}.pub", private_key_path.display()));
    let server_config_path = write_server_config(port, &public_key_path);
    let client_config_path = write_client_config(port, &private_key_path);
    let server_bin = bin_path("bepr-server");
    let client_bin = bin_path("bepr-client");

    let server = Command::new(server_bin)
        .arg("--config")
        .arg(&server_config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr-server");
    let mut server = ChildGuard::new(server);

    let _server_stderr = read_lines(server.child.stderr.take().unwrap());
    wait_for_tcp(port);

    let client = Command::new(client_bin)
        .arg("--config")
        .arg(&client_config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr-client");
    let mut client = ChildGuard::new(client);

    let _client_stderr = read_lines(client.child.stderr.take().unwrap());
    let server_stdout = read_lines(server.child.stdout.take().unwrap());

    writeln!(
        server.child.stdin.as_mut().expect("server stdin"),
        "printf 'bepr-integ-ok\\n'"
    )
    .expect("write command to server stdin");

    assert_line_contains(&server_stdout, "bepr-integ-ok", Duration::from_secs(5));

    client.kill();
    server.kill();
    let _ = fs::remove_file(server_config_path);
    let _ = fs::remove_file(client_config_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

fn build_bins() {
    let status = Command::new("cargo")
        .args(["build", "-p", "bepr-server", "-p", "bepr-client"])
        .status()
        .expect("run cargo build");
    assert!(status.success(), "cargo build failed");
}

fn bin_path(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().expect("current test exe");
    path.pop();
    if path.file_name().and_then(|s| s.to_str()) == Some("deps") {
        path.pop();
    }
    path.push(name);
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("server did not start listening on port {port}");
}

fn generate_ed25519_key(path: &PathBuf) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
}

fn write_server_config(port: u16, public_key_path: &PathBuf) -> PathBuf {
    let path = temp_file("bepr-integ-server-conf");
    fs::write(
        &path,
        format!(
            "bind = 127.0.0.1:{port}\nclient = default, {}\n",
            public_key_path.display()
        ),
    )
    .expect("write server config");
    path
}

fn write_client_config(port: u16, private_key_path: &PathBuf) -> PathBuf {
    let path = temp_file("bepr-integ-client-conf");
    fs::write(
        &path,
        format!(
            "server = ws://127.0.0.1:{port}/agent/default\nprivate_key_path = {}\nshell = /bin/sh\n",
            private_key_path.display()
        ),
    )
    .expect("write client config");
    path
}

fn temp_file(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{name}-{}-{nanos}.txt", std::process::id()))
}

fn read_lines<R: std::io::Read + Send + 'static>(reader: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    let _ = tx.send(line);
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn assert_line_contains(rx: &mpsc::Receiver<String>, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line.contains(needle) => return,
            Ok(line) => seen.push(line),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!("did not see {needle:?}; saw {seen:?}");
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
    }
}
