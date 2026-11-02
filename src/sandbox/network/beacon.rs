//! Analysis of captured network events: raw IPs, uncommon ports, DGA-style
//! names, DNS tunnelling, and beaconing (low-jitter repeated callbacks).

use crate::sandbox::telemetry::{NetworkEvent, NetworkEventKind};
use crate::types::{Finding, Location, Severity};
use std::collections::BTreeMap;

pub fn analyze(events: &[NetworkEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for event in events {
        match event.kind {
            NetworkEventKind::HttpRequest | NetworkEventKind::Connect => {
                if event.destination.parse::<std::net::IpAddr>().is_ok() {
                    push(
                        &mut findings,
                        &mut seen,
                        "sandbox.network.raw-ip",
                        Severity::Medium,
                        0.6,
                        format!("Network connection to raw IP {}", event.destination),
                    );
                }
                if let Some(port) = event.port {
                    if !matches!(port, 53 | 80 | 443 | 8080 | 8443) {
                        push(
                            &mut findings,
                            &mut seen,
                            "sandbox.network.uncommon-port",
                            Severity::Low,
                            0.5,
                            format!(
                                "Connection to {} on uncommon port {}",
                                event.destination, port
                            ),
                        );
                    }
                }
                check_dga(event.destination.as_str(), &mut findings, &mut seen);
            }
            NetworkEventKind::DnsTunnel => {
                push(
                    &mut findings,
                    &mut seen,
                    "sandbox.network.dns-tunnel",
                    Severity::High,
                    0.55,
                    format!(
                        "Oversized DNS query '{}' may be tunnelling data",
                        event.destination
                    ),
                );
            }
            NetworkEventKind::Dns => {
                check_dga(event.destination.as_str(), &mut findings, &mut seen);
            }
        }
    }

    for (destination, timestamps) in repeated_timestamps(events) {
        if let Some((mean, jitter)) = beacon_stats(&timestamps) {
            if mean >= 250.0 && jitter < 0.2 {
                push(
                    &mut findings,
                    &mut seen,
                    "sandbox.network.beacon",
                    Severity::High,
                    0.6,
                    format!(
                        "Repeated callbacks to {} every ~{:.0}ms (jitter {:.0}%)",
                        destination,
                        mean,
                        jitter * 100.0
                    ),
                );
            }
        }
    }

    findings
}

fn check_dga(
    destination: &str,
    findings: &mut Vec<Finding>,
    seen: &mut std::collections::BTreeSet<String>,
) {
    let Some(label) = destination.split('.').next() else {
        return;
    };
    if label.len() >= 12 && entropy(label) > 3.6 {
        push(
            findings,
            seen,
            "sandbox.network.dga",
            Severity::Medium,
            0.55,
            format!(
                "High-entropy domain '{}' resembles an algorithmically generated name",
                destination
            ),
        );
    }
}

fn repeated_timestamps(events: &[NetworkEvent]) -> BTreeMap<String, Vec<u64>> {
    let mut map: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for event in events {
        if matches!(
            event.kind,
            NetworkEventKind::Dns | NetworkEventKind::HttpRequest | NetworkEventKind::Connect
        ) {
            map.entry(event.destination.clone())
                .or_default()
                .push(event.timestamp_ms);
        }
    }
    map.retain(|_, stamps| stamps.len() >= 3);
    map
}

fn beacon_stats(stamps: &[u64]) -> Option<(f64, f64)> {
    let mut sorted = stamps.to_vec();
    sorted.sort_unstable();
    let deltas: Vec<f64> = sorted
        .windows(2)
        .map(|pair| pair[1].saturating_sub(pair[0]) as f64)
        .filter(|delta| *delta >= 50.0)
        .collect();
    if deltas.len() < 2 {
        return None;
    }
    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
    if mean == 0.0 {
        return None;
    }
    let variance = deltas
        .iter()
        .map(|delta| (delta - mean).powi(2))
        .sum::<f64>()
        / deltas.len() as f64;
    Some((mean, variance.sqrt() / mean))
}

fn entropy(value: &str) -> f64 {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn push(
    findings: &mut Vec<Finding>,
    seen: &mut std::collections::BTreeSet<String>,
    rule: &str,
    severity: Severity,
    confidence: f32,
    message: String,
) {
    if !seen.insert(rule.to_string()) {
        return;
    }
    findings.push(Finding {
        id: rule.to_string(),
        severity,
        confidence,
        rule: rule.to_string(),
        category: "sandbox".to_string(),
        location: Location {
            path: "/work".to_string(),
            line: None,
            column: None,
        },
        message,
        snippet: None,
        tags: vec!["sandbox".to_string(), "network".to_string()],
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: NetworkEventKind, destination: &str, port: u16, ts: u64) -> NetworkEvent {
        NetworkEvent {
            pid: None,
            kind,
            destination: destination.to_string(),
            port: Some(port),
            detail: None,
            timestamp_ms: ts,
        }
    }

    #[test]
    fn flags_raw_ip_and_uncommon_port() {
        let events = vec![event(NetworkEventKind::HttpRequest, "203.0.113.9", 4444, 0)];
        let findings = analyze(&events);
        assert!(findings.iter().any(|f| f.rule == "sandbox.network.raw-ip"));
        assert!(findings
            .iter()
            .any(|f| f.rule == "sandbox.network.uncommon-port"));
    }

    #[test]
    fn flags_dga_style_label() {
        let events = vec![event(NetworkEventKind::Dns, "xj3kq9zvb2mwp7.ru", 53, 0)];
        assert!(analyze(&events)
            .iter()
            .any(|f| f.rule == "sandbox.network.dga"));
    }

    #[test]
    fn flags_beaconing() {
        let events = vec![
            event(NetworkEventKind::Dns, "c2.example", 53, 0),
            event(NetworkEventKind::Dns, "c2.example", 53, 1000),
            event(NetworkEventKind::Dns, "c2.example", 53, 2000),
            event(NetworkEventKind::Dns, "c2.example", 53, 3000),
        ];
        assert!(analyze(&events)
            .iter()
            .any(|f| f.rule == "sandbox.network.beacon"));
    }

    #[test]
    fn flags_dns_tunnel() {
        let events = vec![event(
            NetworkEventKind::DnsTunnel,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
            53,
            0,
        )];
        assert!(analyze(&events)
            .iter()
            .any(|f| f.rule == "sandbox.network.dns-tunnel"));
    }

    #[test]
    fn benign_traffic_is_quiet() {
        let events = vec![
            event(NetworkEventKind::HttpRequest, "example.com", 80, 0),
            event(NetworkEventKind::HttpRequest, "cdn.example.com", 443, 500),
        ];
        assert!(analyze(&events).is_empty());
    }
}
