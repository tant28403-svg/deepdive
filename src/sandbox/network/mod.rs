//! Host-side network capture for `NetworkPolicy::Capture`: a logging HTTP
//! proxy, a fake DNS resolver, and the analysis pass over what they saw.

pub mod beacon;
pub mod dns;
pub mod proxy;

use crate::sandbox::telemetry::NetworkEvent;

pub struct Capture {
    proxy: proxy::Proxy,
    dns: dns::Dns,
}

impl Capture {
    pub fn start() -> std::io::Result<Self> {
        Ok(Self {
            proxy: proxy::start()?,
            dns: dns::start()?,
        })
    }

    pub fn stop(&self) {
        self.proxy.stop();
        self.dns.stop();
    }

    pub fn proxy_url(&self) -> String {
        self.proxy.url()
    }

    pub fn dns_addr(&self) -> std::net::SocketAddr {
        self.dns.addr
    }

    /// All captured events, ordered by the time they were seen.
    pub fn events(&self) -> Vec<NetworkEvent> {
        let mut events = Vec::new();
        if let Ok(proxy) = self.proxy.events.lock() {
            events.extend(proxy.iter().cloned());
        }
        if let Ok(dns) = self.dns.events.lock() {
            events.extend(dns.iter().cloned());
        }
        events.sort_by_key(|event| event.timestamp_ms);
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_starts_and_reports_endpoints() {
        let capture = Capture::start().unwrap();
        assert!(capture.proxy_url().starts_with("http://127.0.0.1:"));
        assert_ne!(capture.dns_addr().port(), 0);
        capture.stop();
    }
}
