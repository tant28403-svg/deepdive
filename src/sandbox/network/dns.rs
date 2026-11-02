//! Fake DNS resolver for sandboxed runs. Every query is logged and answered
//! with NXDOMAIN, so name-based beaconing/DGA behaviour is visible even when
//! the process never completes a connection.

use crate::sandbox::telemetry::{NetworkEvent, NetworkEventKind};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Dns {
    pub addr: SocketAddr,
    pub events: Arc<Mutex<Vec<NetworkEvent>>>,
    shutdown: Arc<AtomicBool>,
}

pub fn start() -> std::io::Result<Dns> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let addr = socket.local_addr()?;
    let events: Arc<Mutex<Vec<NetworkEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(AtomicBool::new(false));

    let thread_events = events.clone();
    let thread_shutdown = shutdown.clone();
    std::thread::spawn(move || {
        let start = Instant::now();
        let mut buffer = [0u8; 4096];
        while !thread_shutdown.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buffer) {
                Ok((len, peer)) => {
                    if let Some((name, question_end)) = parse_question(&buffer[..len]) {
                        record(&thread_events, start, &name);
                        let _ = socket.send_to(&nxdomain(&buffer[..len], question_end), peer);
                    }
                }
                Err(err)
                    if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut => {
                }
                Err(_) => break,
            }
        }
    });

    Ok(Dns {
        addr,
        events,
        shutdown,
    })
}

impl Dns {
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

pub fn parse_question(packet: &[u8]) -> Option<(String, usize)> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut labels = Vec::new();
    let mut cursor = 12usize;
    loop {
        let len = *packet.get(cursor)? as usize;
        cursor += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer in a query: stop here.
            cursor += 1;
            break;
        }
        if cursor + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[cursor..cursor + len]).to_string());
        cursor += len;
    }
    if cursor + 4 > packet.len() {
        return None;
    }
    Some((labels.join("."), cursor + 4))
}

fn nxdomain(query: &[u8], question_end: usize) -> Vec<u8> {
    let mut response = vec![0u8; 12];
    response[0] = query[0];
    response[1] = query[1];
    let rd = query[2] & 0x01;
    response[2] = 0x80 | rd; // QR=1, RD copied
    response[3] = 0x83; // RA=1, rcode=3 (NXDOMAIN)
    response[5] = 1; // QDCOUNT
    response.extend_from_slice(&query[12..question_end.min(query.len())]);
    response
}

fn record(events: &Arc<Mutex<Vec<NetworkEvent>>>, start: Instant, name: &str) {
    let kind = if name.len() > 50 || name.split('.').any(|label| label.len() > 30) {
        NetworkEventKind::DnsTunnel
    } else {
        NetworkEventKind::Dns
    };
    let event = NetworkEvent {
        pid: None,
        kind,
        destination: name.to_string(),
        port: Some(53),
        detail: Some("query".to_string()),
        timestamp_ms: start.elapsed().as_millis() as u64,
    };
    if let Ok(mut guard) = events.lock() {
        if guard.len() < 10_000 {
            guard.push(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        packet
    }

    #[test]
    fn parses_a_question() {
        let packet = query("example.com");
        let (name, end) = parse_question(&packet).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, packet.len());
    }

    #[test]
    fn answers_with_nxdomain() {
        let packet = query("example.com");
        let (_, end) = parse_question(&packet).unwrap();
        let response = nxdomain(&packet, end);
        assert_eq!(response[2] & 0x80, 0x80);
        assert_eq!(response[3] & 0x0F, 3);
    }

    #[test]
    fn flags_long_labels_as_tunnels() {
        let long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com";
        let packet = query(long);
        let (name, _) = parse_question(&packet).unwrap();
        assert_eq!(name, long);
    }
}
