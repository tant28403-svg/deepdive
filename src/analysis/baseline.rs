//! Compare a scan against a previous JSON report.
//!
//! Findings are fingerprinted by rule + path + line so that a finding which
//! only moved within a file still counts as new, while unchanged findings are
//! recognised across runs.

use crate::types::Finding;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Report {
    #[serde(default)]
    findings: Vec<Finding>,
}

#[derive(Debug, Default)]
pub struct BaselineDiff {
    pub new: Vec<Finding>,
    pub resolved: Vec<String>,
}

impl BaselineDiff {
    #[allow(dead_code)] // used by tests and available to library callers
    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.resolved.is_empty()
    }

    pub fn highest_new_severity(&self) -> Option<crate::types::Severity> {
        self.new.iter().map(|f| f.severity).max()
    }
}

pub fn load(path: &Path) -> Result<Vec<Finding>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read baseline {}", path.display()))?;
    let report: Report = serde_json::from_str(&content)
        .with_context(|| format!("parse baseline {}", path.display()))?;
    Ok(report.findings)
}

pub fn fingerprint(finding: &Finding) -> String {
    format!(
        "{}|{}|{}",
        finding.rule,
        finding.location.path,
        finding.location.line.unwrap_or(0)
    )
}

pub fn compare(current: &[Finding], baseline: &[Finding]) -> BaselineDiff {
    let baseline_keys: BTreeSet<String> = baseline.iter().map(fingerprint).collect();
    let current_keys: BTreeSet<String> = current.iter().map(fingerprint).collect();

    let mut diff = BaselineDiff::default();
    for finding in current {
        if !baseline_keys.contains(&fingerprint(finding)) {
            diff.new.push(finding.clone());
        }
    }
    for finding in baseline {
        let key = fingerprint(finding);
        if !current_keys.contains(&key) {
            diff.resolved.push(key);
        }
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Location, Severity};

    fn finding(rule: &str, path: &str, severity: Severity) -> Finding {
        Finding {
            id: format!("{}-{}", rule, path),
            severity,
            confidence: 0.9,
            rule: rule.to_string(),
            category: "test".to_string(),
            location: Location {
                path: path.to_string(),
                line: None,
                column: None,
            },
            message: String::new(),
            snippet: None,
            tags: vec![],
        }
    }

    #[test]
    fn detects_new_and_resolved_findings() {
        let baseline = vec![
            finding("secrets.key", "/repo/a.js", Severity::High),
            finding("deps.osv", "/repo/package-lock.json", Severity::Medium),
        ];
        let current = vec![
            finding("secrets.key", "/repo/a.js", Severity::High),
            finding("ast.tainted", "/repo/a.js", Severity::High),
        ];
        let diff = compare(&current, &baseline);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.new[0].rule, "ast.tainted");
        assert_eq!(diff.resolved.len(), 1);
        assert!(diff.resolved[0].starts_with("deps.osv"));
        assert!(!diff.is_empty());
        assert_eq!(diff.highest_new_severity(), Some(Severity::High));
    }

    #[test]
    fn identical_reports_are_empty() {
        let findings = vec![finding("secrets.key", "/repo/a.js", Severity::Low)];
        assert!(compare(&findings, &findings).is_empty());
    }
}
