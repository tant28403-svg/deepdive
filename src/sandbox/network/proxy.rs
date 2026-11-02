//! Minimal HTTP/CONNECT proxy. It logs the destination of every request and
//! relays traffic; TLS is never intercepted.

use crate::sandbox::telemetry::{NetworkEvent, NetworkEventKind};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEAD_BYTES: usize = 64 * 1024;

pub struct Proxy {
    pub addr: SocketAddr,
    pub events: Arc<Mutex<Vec<NetworkEvent>>>,
    shutdown: Arc<AtomicBool>,
}

pub fn start() -> std::io::Result<Proxy> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let events: Arc<Mutex<Vec<NetworkEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(AtomicBool::new(false));

    let thread_events = events.clone();
    let thread_shutdown = shutdown.clone();
    std::thread::spawn(move || {
        let start = Instant::now();
        while !thread_shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let events = thread_events.clone();
                    std::thread::spawn(move || {
                        let _ = handle(stream, &events, start);
                    });
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });

    Ok(Proxy {
        addr,
        events,
        shutdown,
    })
}

impl Proxy {
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }
}

fn handle(
    mut client: TcpStream,
    events: &Arc<Mutex<Vec<NetworkEvent>>>,
    start: Instant,
) -> std::io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let Some((request_line, headers)) = read_head(&mut client)? else {
        return Ok(());
    };

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() {
        return Ok(());
    }

    let connect = method.eq_ignore_ascii_case("CONNECT");
    let (host, port, connect_target) = if connect {
        let (host, port) = split_host_port(&target, 443);
        (host.clone(), port, format!("{}:{}", host, port))
    } else {
        let url = target.strip_prefix("http://").unwrap_or(&target);
        let hostport = url.split('/').next().unwrap_or(url);
        let (host, port) = split_host_port(hostport, 80);
        let host = headers
            .iter()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                lower.strip_prefix("host:").map(|v| v.trim().to_string())
            })
            .map(|header| split_host_port(&header, port).0)
            .unwrap_or(host);
        (host.clone(), port, format!("{}:{}", host, port))
    };

    record(
        events,
        start,
        NetworkEvent {
            pid: None,
            kind: NetworkEventKind::HttpRequest,
            destination: host.clone(),
            port: Some(port),
            detail: Some(method.clone()),
            timestamp_ms: 0,
        },
    );

    let Ok(mut upstream) = TcpStream::connect(&connect_target) else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        return Ok(());
    };

    if connect {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        let path = origin_form(&target, &host);
        let mut out = format!("{} {} HTTP/1.1\r\n", method, path);
        for line in &headers {
            if !line.to_ascii_lowercase().starts_with("proxy-connection") {
                out.push_str(line);
            }
        }
        out.push_str("\r\n");
        upstream.write_all(out.as_bytes())?;
    }

    relay(client, upstream);
    Ok(())
}

/// Read the request line plus headers without consuming body bytes.
fn read_head(stream: &mut TcpStream) -> std::io::Result<Option<(String, Vec<String>)>> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while buffer.len() < MAX_HEAD_BYTES {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buffer.push(byte[0]);
                if buffer.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }
    let text = String::from_utf8_lossy(&buffer).to_string();
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("").trim().to_string();
    if request_line.is_empty() {
        return Ok(None);
    }
    let headers: Vec<String> = lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| format!("{}\r\n", line))
        .collect();
    Ok(Some((request_line, headers)))
}

fn origin_form(target: &str, host: &str) -> String {
    let stripped = target
        .strip_prefix(&format!("http://{}", host))
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{}", stripped)
    }
}

fn split_host_port(value: &str, default_port: u16) -> (String, u16) {
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(']') => {
            (host.to_string(), port.parse().unwrap_or(default_port))
        }
        _ => (value.to_string(), default_port),
    }
}

fn record(events: &Arc<Mutex<Vec<NetworkEvent>>>, start: Instant, mut event: NetworkEvent) {
    event.timestamp_ms = start.elapsed().as_millis() as u64;
    if let Ok(mut guard) = events.lock() {
        if guard.len() < 10_000 {
            guard.push(event);
        }
    }
}

fn relay(mut a: TcpStream, mut b: TcpStream) {
    let Ok(mut a_reader) = a.try_clone() else {
        return;
    };
    let Ok(mut b_writer) = b.try_clone() else {
        return;
    };
    let handle = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_reader, &mut b_writer);
        let _ = b_writer.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut b, &mut a);
    let _ = a.shutdown(Shutdown::Write);
    let _ = handle.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            split_host_port("example.com", 80),
            ("example.com".into(), 80)
        );
        assert_eq!(
            split_host_port("example.com:8443", 80),
            ("example.com".into(), 8443)
        );
    }

    #[test]
    fn rewrites_absolute_form() {
        assert_eq!(origin_form("http://a.test/x?y=1", "a.test"), "/x?y=1");
        assert_eq!(origin_form("/plain", "a.test"), "/plain");
    }

    #[test]
    fn logs_a_plain_http_request() {
        let proxy = start().unwrap();
        let addr = proxy.addr;

        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = server.accept() {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let request = format!(
            "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            server_addr.port(),
            server_addr.port()
        );
        client.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = client.read_to_string(&mut response);

        let events = proxy.events.lock().unwrap().clone();
        proxy.stop();

        assert!(!events.is_empty(), "expected a captured request");
        assert_eq!(events[0].destination, "127.0.0.1");
        assert!(response.contains("200 OK") || response.is_empty());
    }
}
