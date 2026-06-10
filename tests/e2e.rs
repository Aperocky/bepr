use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    sync::{Mutex as StdMutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const OPERATOR_SOCKET: &str = "/tmp/bepr.sock";

#[test]
fn authenticated_client_pipes_shell_output_to_server() {
    let _test_guard = test_lock().lock().unwrap_or_else(|err| err.into_inner());
    build_bin();
    let _socket_guard = TestSocketGuard::new();

    let port = free_port();
    let private_key_path = temp_file("bepr-integ-id-ed25519");
    generate_ed25519_key(&private_key_path);
    let public_key_path = PathBuf::from(format!("{}.pub", private_key_path.display()));
    let key_dir = temp_dir("bepr-integ-keys");
    fs::create_dir(&key_dir).expect("create key dir");
    fs::copy(&public_key_path, key_dir.join("default.pub")).expect("copy public key");
    let tls_cert_path = temp_file("bepr-integ-tls-cert");
    let tls_key_path = temp_file("bepr-integ-tls-key");
    generate_self_signed_cert(&tls_cert_path, &tls_key_path);
    let server_config_path = write_server_config(port, &key_dir, &tls_cert_path, &tls_key_path);
    let client_config_path = write_client_config(port, &private_key_path);
    let bepr_bin = bin_path("bepr");

    let server = Command::new(&bepr_bin)
        .arg("server")
        .arg("--config")
        .arg(&server_config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr server");
    let mut server = ChildGuard::new(server);

    let server_stderr = read_lines(server.child.stderr.take().unwrap());
    wait_for_tcp(port);

    let client = Command::new(&bepr_bin)
        .arg("client")
        .arg("--config")
        .arg(&client_config_path)
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr client");
    let mut client = ChildGuard::new(client);

    let _client_stderr = read_lines(client.child.stderr.take().unwrap());
    assert_line_contains(&server_stderr, "authenticated default", Duration::from_secs(5));

    let list = Command::new(&bepr_bin)
        .arg("list")
        .arg("--socket")
        .arg(OPERATOR_SOCKET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr list");
    let mut list = ChildGuard::new(list);
    let list_stdout = read_lines(list.child.stdout.take().unwrap());
    let _list_stderr = read_lines(list.child.stderr.take().unwrap());
    assert_line_contains(&list_stdout, "default", Duration::from_secs(5));
    list.kill();

    let connect = Command::new(&bepr_bin)
        .arg("connect")
        .arg("--socket")
        .arg(OPERATOR_SOCKET)
        .arg("default")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr connect");
    let mut connect = ChildGuard::new(connect);
    let connect_stdout = read_lines(connect.child.stdout.take().unwrap());
    let _connect_stderr = read_lines(connect.child.stderr.take().unwrap());

    writeln!(
        connect.child.stdin.as_mut().expect("connect stdin"),
        "printf 'bepr-integ-ok\\n'"
    )
    .expect("write command to connect stdin");

    assert_line_contains(&connect_stdout, "bepr-integ-ok", Duration::from_secs(5));

    writeln!(connect.child.stdin.as_mut().expect("connect stdin"), "exit")
        .expect("write exit to connect stdin");
    assert_line_contains(&server_stderr, "disconnected default", Duration::from_secs(5));
    wait_for_child_exit(&mut connect.child, Duration::from_secs(5));

    client.kill();
    server.kill();
    let _ = fs::remove_file(server_config_path);
    let _ = fs::remove_file(client_config_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
    let _ = fs::remove_file(tls_cert_path);
    let _ = fs::remove_file(tls_key_path);
    let _ = fs::remove_dir_all(key_dir);
}

#[test]
fn client_disconnect_clears_session_and_allows_reconnect() {
    let _test_guard = test_lock().lock().unwrap_or_else(|err| err.into_inner());
    build_bin();
    let _socket_guard = TestSocketGuard::new();

    let port = free_port();
    let private_key_path = temp_file("bepr-heartbeat-id-ed25519");
    generate_ed25519_key(&private_key_path);
    let public_key_path = PathBuf::from(format!("{}.pub", private_key_path.display()));
    let key_dir = temp_dir("bepr-heartbeat-keys");
    fs::create_dir(&key_dir).expect("create key dir");
    fs::copy(&public_key_path, key_dir.join("default.pub")).expect("copy public key");
    let tls_cert_path = temp_file("bepr-heartbeat-tls-cert");
    let tls_key_path = temp_file("bepr-heartbeat-tls-key");
    generate_self_signed_cert(&tls_cert_path, &tls_key_path);
    let server_config_path = write_server_config(port, &key_dir, &tls_cert_path, &tls_key_path);
    let client_config_path = write_client_config(port, &private_key_path);
    let bepr_bin = bin_path("bepr");

    let server = Command::new(&bepr_bin)
        .arg("server")
        .arg("--config")
        .arg(&server_config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr server");
    let mut server = ChildGuard::new(server);

    let server_stderr = read_lines(server.child.stderr.take().unwrap());
    wait_for_tcp(port);

    let client = Command::new(&bepr_bin)
        .arg("client")
        .arg("--config")
        .arg(&client_config_path)
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr client");
    let mut client = ChildGuard::new(client);

    let _client_stderr = read_lines(client.child.stderr.take().unwrap());
    assert_line_contains(&server_stderr, "authenticated default", Duration::from_secs(5));

    let list = Command::new(&bepr_bin)
        .arg("list")
        .arg("--socket")
        .arg(OPERATOR_SOCKET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr list");
    let mut list = ChildGuard::new(list);
    let list_stdout = read_lines(list.child.stdout.take().unwrap());
    let _list_stderr = read_lines(list.child.stderr.take().unwrap());
    assert_line_contains(&list_stdout, "default", Duration::from_secs(5));
    list.kill();

    client.kill();
    assert_line_contains(&server_stderr, "disconnected default", Duration::from_secs(5));

    let list = Command::new(&bepr_bin)
        .arg("list")
        .arg("--socket")
        .arg(OPERATOR_SOCKET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr list after disconnect");
    let mut list = ChildGuard::new(list);
    let list_stdout = read_lines(list.child.stdout.take().unwrap());
    let _list_stderr = read_lines(list.child.stderr.take().unwrap());
    assert_line_contains(&list_stdout, "default", Duration::from_secs(5));
    list.kill();

    let client = Command::new(&bepr_bin)
        .arg("client")
        .arg("--config")
        .arg(&client_config_path)
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("restart bepr client");
    let mut client = ChildGuard::new(client);
    let _client_stderr = read_lines(client.child.stderr.take().unwrap());
    assert_line_contains(&server_stderr, "authenticated default", Duration::from_secs(10));

    let list = Command::new(&bepr_bin)
        .arg("list")
        .arg("--socket")
        .arg(OPERATOR_SOCKET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr list after reconnect");
    let mut list = ChildGuard::new(list);
    let list_stdout = read_lines(list.child.stdout.take().unwrap());
    let _list_stderr = read_lines(list.child.stderr.take().unwrap());
    assert_line_contains(&list_stdout, "default", Duration::from_secs(10));
    list.kill();

    client.kill();
    server.kill();
    let _ = fs::remove_file(server_config_path);
    let _ = fs::remove_file(client_config_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
    let _ = fs::remove_file(tls_cert_path);
    let _ = fs::remove_file(tls_key_path);
    let _ = fs::remove_dir_all(key_dir);
}

#[test]
fn terminal_connect_pipes_tty_input_and_exits() {
    let _test_guard = test_lock().lock().unwrap_or_else(|err| err.into_inner());
    build_bin();
    let _socket_guard = TestSocketGuard::new();

    if !has_script_command() {
        eprintln!("skipping terminal input test: script command not found");
        return;
    }

    let port = free_port();
    let private_key_path = temp_file("bepr-tty-id-ed25519");
    generate_ed25519_key(&private_key_path);
    let public_key_path = PathBuf::from(format!("{}.pub", private_key_path.display()));
    let key_dir = temp_dir("bepr-tty-keys");
    fs::create_dir(&key_dir).expect("create key dir");
    fs::copy(&public_key_path, key_dir.join("default.pub")).expect("copy public key");
    let tls_cert_path = temp_file("bepr-tty-tls-cert");
    let tls_key_path = temp_file("bepr-tty-tls-key");
    generate_self_signed_cert(&tls_cert_path, &tls_key_path);
    let server_config_path = write_server_config(port, &key_dir, &tls_cert_path, &tls_key_path);
    let client_config_path = write_client_config(port, &private_key_path);
    let bepr_bin = bin_path("bepr");

    let server = Command::new(&bepr_bin)
        .arg("server")
        .arg("--config")
        .arg(&server_config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr server");
    let mut server = ChildGuard::new(server);

    let server_stderr = read_lines(server.child.stderr.take().unwrap());
    wait_for_tcp(port);

    let client = Command::new(&bepr_bin)
        .arg("client")
        .arg("--config")
        .arg(&client_config_path)
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bepr client");
    let mut client = ChildGuard::new(client);

    let _client_stderr = read_lines(client.child.stderr.take().unwrap());
    assert_line_contains(&server_stderr, "authenticated default", Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(250));

    let mut connect = spawn_tty_connect(&bepr_bin, "default").expect("spawn tty bepr connect");
    let connect_stdout = read_chunks(connect.child.stdout.take().unwrap());
    let _connect_stderr = read_lines(connect.child.stderr.take().unwrap());

    assert_chunk_contains_any(&connect_stdout, &["$ ", "# "], Duration::from_secs(5));
    write!(
        connect.child.stdin.as_mut().expect("connect stdin"),
        "printf 'bepr-tty-ok\\n'\r"
    )
    .expect("write command to tty connect stdin");
    assert_chunk_contains(&connect_stdout, "bepr-tty-ok", Duration::from_secs(5));

    write!(connect.child.stdin.as_mut().expect("connect stdin"), "exit\r")
        .expect("write exit to tty connect stdin");
    wait_for_child_exit(&mut connect.child, Duration::from_secs(5));

    client.kill();
    server.kill();
    let _ = fs::remove_file(server_config_path);
    let _ = fs::remove_file(client_config_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
    let _ = fs::remove_file(tls_cert_path);
    let _ = fs::remove_file(tls_key_path);
    let _ = fs::remove_dir_all(key_dir);
}

#[test]
fn network_operator_connects_and_pipes_shell_output() {
    let _test_guard = test_lock().lock().unwrap_or_else(|err| err.into_inner());
    build_bin();
    let _socket_guard = TestSocketGuard::new();

    let port = free_port();
    let client_key_path = temp_file("bepr-netop-client-id-ed25519");
    generate_ed25519_key(&client_key_path);
    let client_pub_path = PathBuf::from(format!("{}.pub", client_key_path.display()));
    let user_key_path = temp_file("bepr-netop-user-id-ed25519");
    generate_ed25519_key(&user_key_path);
    let user_pub_path = PathBuf::from(format!("{}.pub", user_key_path.display()));

    let client_key_dir = temp_dir("bepr-netop-client-keys");
    fs::create_dir(&client_key_dir).expect("create client key dir");
    fs::copy(&client_pub_path, client_key_dir.join("default.pub")).expect("copy client public key");

    let user_key_dir = temp_dir("bepr-netop-user-keys");
    fs::create_dir(&user_key_dir).expect("create user key dir");
    fs::copy(&user_pub_path, user_key_dir.join("operator.pub")).expect("copy user public key");

    let tls_cert_path = temp_file("bepr-netop-tls-cert");
    let tls_key_path = temp_file("bepr-netop-tls-key");
    generate_self_signed_cert(&tls_cert_path, &tls_key_path);

    let server_config_path = write_server_config_full(port, &client_key_dir, Some(&user_key_dir), &tls_cert_path, &tls_key_path);
    let client_config_path = write_client_config(port, &client_key_path);
    let bepr_bin = bin_path("bepr");

    let server = Command::new(&bepr_bin)
        .args(["server", "--config"]).arg(&server_config_path)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn bepr server");
    let mut server = ChildGuard::new(server);
    let server_stderr = read_lines(server.child.stderr.take().unwrap());
    wait_for_tcp(port);

    let client = Command::new(&bepr_bin)
        .args(["client", "--config"]).arg(&client_config_path)
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped())
        .spawn().expect("spawn bepr client");
    let mut client = ChildGuard::new(client);
    let _client_stderr = read_lines(client.child.stderr.take().unwrap());
    assert_line_contains(&server_stderr, "authenticated default", Duration::from_secs(5));

    let wss_socket = format!("wss://127.0.0.1:{port}/bepr/user/operator");
    let connect = Command::new(&bepr_bin)
        .arg("connect")
        .arg("--socket").arg(&wss_socket)
        .arg("--key").arg(&user_key_path)
        .arg("default")
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn bepr connect (network operator)");
    let mut connect = ChildGuard::new(connect);
    let connect_stdout = read_lines(connect.child.stdout.take().unwrap());
    let _connect_stderr = read_lines(connect.child.stderr.take().unwrap());

    writeln!(
        connect.child.stdin.as_mut().expect("connect stdin"),
        "printf 'bepr-netop-ok\\n'"
    ).expect("write command to connect stdin");
    assert_line_contains(&connect_stdout, "bepr-netop-ok", Duration::from_secs(5));

    writeln!(connect.child.stdin.as_mut().expect("connect stdin"), "exit")
        .expect("write exit to connect stdin");
    assert_line_contains(&server_stderr, "detached from default", Duration::from_secs(5));
    wait_for_child_exit(&mut connect.child, Duration::from_secs(5));

    client.kill();
    server.kill();
    let _ = fs::remove_file(server_config_path);
    let _ = fs::remove_file(client_config_path);
    let _ = fs::remove_file(&client_key_path);
    let _ = fs::remove_file(&client_pub_path);
    let _ = fs::remove_file(&user_key_path);
    let _ = fs::remove_file(&user_pub_path);
    let _ = fs::remove_file(tls_cert_path);
    let _ = fs::remove_file(tls_key_path);
    let _ = fs::remove_dir_all(client_key_dir);
    let _ = fs::remove_dir_all(user_key_dir);
}

#[test]
fn network_operator_uses_user_config_when_no_flags() {
    let _test_guard = test_lock().lock().unwrap_or_else(|err| err.into_inner());
    build_bin();
    let _socket_guard = TestSocketGuard::new();

    let port = free_port();
    let client_key_path = temp_file("bepr-ucfg-client-id-ed25519");
    generate_ed25519_key(&client_key_path);
    let client_pub_path = PathBuf::from(format!("{}.pub", client_key_path.display()));
    let user_key_path = temp_file("bepr-ucfg-user-id-ed25519");
    generate_ed25519_key(&user_key_path);
    let user_pub_path = PathBuf::from(format!("{}.pub", user_key_path.display()));

    let client_key_dir = temp_dir("bepr-ucfg-client-keys");
    fs::create_dir(&client_key_dir).expect("create client key dir");
    fs::copy(&client_pub_path, client_key_dir.join("default.pub")).expect("copy client public key");

    let user_key_dir = temp_dir("bepr-ucfg-user-keys");
    fs::create_dir(&user_key_dir).expect("create user key dir");
    fs::copy(&user_pub_path, user_key_dir.join("operator.pub")).expect("copy user public key");

    let tls_cert_path = temp_file("bepr-ucfg-tls-cert");
    let tls_key_path = temp_file("bepr-ucfg-tls-key");
    generate_self_signed_cert(&tls_cert_path, &tls_key_path);

    let server_config_path = write_server_config_full(port, &client_key_dir, Some(&user_key_dir), &tls_cert_path, &tls_key_path);
    let client_config_path = write_client_config(port, &client_key_path);

    let fake_home = temp_dir("bepr-ucfg-home");
    fs::create_dir(&fake_home).expect("create fake home");
    write_user_config(port, &user_key_path, &fake_home);

    let bepr_bin = bin_path("bepr");

    let server = Command::new(&bepr_bin)
        .args(["server", "--config"]).arg(&server_config_path)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn bepr server");
    let mut server = ChildGuard::new(server);
    let server_stderr = read_lines(server.child.stderr.take().unwrap());
    wait_for_tcp(port);

    let client = Command::new(&bepr_bin)
        .args(["client", "--config"]).arg(&client_config_path)
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped())
        .spawn().expect("spawn bepr client");
    let mut client = ChildGuard::new(client);
    let _client_stderr = read_lines(client.child.stderr.take().unwrap());
    assert_line_contains(&server_stderr, "authenticated default", Duration::from_secs(5));

    // connect with no --socket or --key; should fall back to user.conf via fake HOME
    let connect = Command::new(&bepr_bin)
        .arg("connect")
        .arg("default")
        .env("HOME", &fake_home)
        .env("BEPR_INSECURE_SKIP_TLS_VERIFY", "1")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn bepr connect (from user config)");
    let mut connect = ChildGuard::new(connect);
    let connect_stdout = read_lines(connect.child.stdout.take().unwrap());
    let _connect_stderr = read_lines(connect.child.stderr.take().unwrap());

    writeln!(
        connect.child.stdin.as_mut().expect("connect stdin"),
        "printf 'bepr-ucfg-ok\\n'"
    ).expect("write command to connect stdin");
    assert_line_contains(&connect_stdout, "bepr-ucfg-ok", Duration::from_secs(5));

    writeln!(connect.child.stdin.as_mut().expect("connect stdin"), "exit")
        .expect("write exit to connect stdin");
    assert_line_contains(&server_stderr, "detached from default", Duration::from_secs(5));
    wait_for_child_exit(&mut connect.child, Duration::from_secs(5));

    client.kill();
    server.kill();
    let _ = fs::remove_file(server_config_path);
    let _ = fs::remove_file(client_config_path);
    let _ = fs::remove_file(&client_key_path);
    let _ = fs::remove_file(&client_pub_path);
    let _ = fs::remove_file(&user_key_path);
    let _ = fs::remove_file(&user_pub_path);
    let _ = fs::remove_file(tls_cert_path);
    let _ = fs::remove_file(tls_key_path);
    let _ = fs::remove_dir_all(client_key_dir);
    let _ = fs::remove_dir_all(user_key_dir);
    let _ = fs::remove_dir_all(fake_home);
}

fn build_bin() {
    static BUILD: OnceLock<()> = OnceLock::new();
    BUILD.get_or_init(|| {
        let status = Command::new("cargo")
            .args(["build", "-p", "bepr"])
            .status()
            .expect("run cargo build");
        assert!(status.success(), "cargo build failed");
    });
}

fn has_script_command() -> bool {
    Command::new("sh")
        .arg("-c")
        .arg("command -v script >/dev/null 2>&1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn spawn_tty_connect(bepr_bin: &PathBuf, client_id: &str) -> std::io::Result<ChildGuard> {
    let mut command = Command::new("script");
    if cfg!(target_os = "macos") {
        command
            .arg("-q")
            .arg("/dev/null")
            .arg(bepr_bin)
            .arg("connect")
            .arg("--socket")
            .arg(OPERATOR_SOCKET)
            .arg(client_id);
    } else {
        command
            .arg("-q")
            .arg("-c")
            .arg(format!("{} connect --socket {} {}", shell_quote(bepr_bin), OPERATOR_SOCKET, client_id))
            .arg("/dev/null");
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(ChildGuard::new)
}

fn shell_quote(path: &PathBuf) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
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

fn generate_self_signed_cert(cert_path: &PathBuf, key_path: &PathBuf) {
    let status = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path.to_str().unwrap(),
            "-out", cert_path.to_str().unwrap(),
            "-days", "1",
            "-nodes",
            "-subj", "/CN=localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run openssl req");
    assert!(status.success(), "openssl req failed");
}

fn write_server_config(port: u16, key_dir: &PathBuf, tls_cert: &PathBuf, tls_key: &PathBuf) -> PathBuf {
    write_server_config_full(port, key_dir, None, tls_cert, tls_key)
}

fn write_server_config_full(port: u16, key_dir: &PathBuf, user_key_dir: Option<&PathBuf>, tls_cert: &PathBuf, tls_key: &PathBuf) -> PathBuf {
    let path = temp_file("bepr-integ-server-conf");
    let mut content = format!(
        "bind = 127.0.0.1:{port}\nkey_dir = {}\ntls_cert = {}\ntls_key = {}\n",
        key_dir.display(), tls_cert.display(), tls_key.display(),
    );
    if let Some(dir) = user_key_dir {
        content.push_str(&format!("user_key_dir = {}\n", dir.display()));
    }
    fs::write(&path, content).expect("write server config");
    path
}

fn write_user_config(port: u16, user_key_path: &PathBuf, fake_home: &PathBuf) -> PathBuf {
    let config_dir = fake_home.join(".config/bepr");
    fs::create_dir_all(&config_dir).expect("create user config dir");
    let path = config_dir.join("user.conf");
    fs::write(
        &path,
        format!(
            "server = wss://127.0.0.1:{port}/bepr/user/operator\nprivate_key_path = {}\n",
            user_key_path.display()
        ),
    )
    .expect("write user config");
    path
}

fn write_client_config(port: u16, private_key_path: &PathBuf) -> PathBuf {
    let path = temp_file("bepr-integ-client-conf");
    fs::write(
        &path,
        format!(
            "server = wss://127.0.0.1:{port}/bepr/client/default\nprivate_key_path = {}\nshell = /bin/sh\n",
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

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{name}-{}-{nanos}", std::process::id()))
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

fn read_chunks<R: std::io::Read + Send + 'static>(mut reader: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0_u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                    let _ = tx.send(chunk);
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

fn assert_chunk_contains(rx: &mpsc::Receiver<String>, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut seen = String::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(chunk) => {
                seen.push_str(&chunk);
                if seen.contains(needle) {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!("did not see {needle:?}; saw {seen:?}");
}

fn assert_chunk_contains_any(
    rx: &mpsc::Receiver<String>,
    needles: &[&str],
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let mut seen = String::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(chunk) => {
                seen.push_str(&chunk);
                if needles.iter().any(|needle| seen.contains(needle)) {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!("did not see any of {needles:?}; saw {seen:?}");
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait().expect("check child exit") {
            Some(status) => {
                assert!(status.success(), "child exited with {status}");
                return;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    panic!("child did not exit");
}

fn test_lock() -> &'static StdMutex<()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
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

struct TestSocketGuard;

impl TestSocketGuard {
    fn new() -> Self {
        let _ = fs::remove_file(OPERATOR_SOCKET);
        Self
    }
}

impl Drop for TestSocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(OPERATOR_SOCKET);
    }
}
