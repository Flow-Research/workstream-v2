use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn scrape(port: u16, path: &str) -> std::io::Result<String> {
    let mut socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    socket.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn running_node_exposes_health_and_counts_real_rpc_traffic() {
    let reserve = || TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let (a, b) = (reserve(), reserve());
    let metrics = a.local_addr().unwrap().port();
    let rpc = b.local_addr().unwrap().port();
    drop((a, b));
    let mut node = Node(
        Command::new(env!("CARGO_BIN_EXE_node"))
            .env("WORKSTREAM_NODE_RPC_PORT", rpc.to_string())
            .args(["--metrics-port", &metrics.to_string()])
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !scrape(metrics, "/readyz").is_ok_and(|r| r.starts_with("HTTP/1.1 200")) {
        assert!(
            Instant::now() < deadline && node.0.try_wait().unwrap().is_none(),
            "node did not become ready"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(scrape(metrics, "/healthz")
        .unwrap()
        .starts_with("HTTP/1.1 200"));
    let mut rpc = BufReader::new(TcpStream::connect(("127.0.0.1", rpc)).unwrap());
    rpc.get_ref()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    for method in ["workstream.prover.getStatus", "unknown"] {
        writeln!(
            rpc.get_mut(),
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#
        )
        .unwrap();
        let mut response = String::new();
        assert!(rpc.read_line(&mut response).unwrap() > 0);
    }
    let metrics = scrape(metrics, "/metrics").unwrap();
    for expected in [
        "workstream_ready 1",
        "workstream_rpc_requests_total 2",
        "workstream_rpc_errors_total 1",
    ] {
        assert!(metrics.lines().any(|line| line == expected), "{metrics}");
    }
}
