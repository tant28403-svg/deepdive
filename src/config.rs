use crate::types::{Finding, Severity};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Global user configuration (`<config>/deepdive/config.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub min_severity: Option<String>,
    pub offline: Option<bool>,
    #[serde(default)]
    pub rules: Vec<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let Some(path) = config_dir().map(|d| d.join("config.toml")) else {
            return Ok(Config::default());
        };
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(toml::from_str(&content)?)
    }
}

/// Per-project configuration (`.deepdive.toml` at the scan root or a parent).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProjectConfig {
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub disable_rules: Vec<String>,
    #[serde(default)]
    pub severity_overrides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowRule {
    /// Rule id or glob (`secrets.*`). Omit to match any rule.
    #[serde(default)]
    pub rule: Option<String>,
    /// Path substring or glob. Omit to match any path.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl ProjectConfig {
    pub fn load(root: &Path) -> Self {
        let start = if root.is_dir() {
            root
        } else {
            root.parent().unwrap_or(root)
        };
        for dir in start.ancestors().take(8) {
            let path = dir.join(".deepdive.toml");
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(cfg) = toml::from_str::<ProjectConfig>(&content) {
                        return cfg;
                    }
                }
            }
        }
        Self::default()
    }

    /// Drop allowlisted findings and apply severity overrides. Returns how many were suppressed.
    pub fn apply(&self, findings: &mut Vec<Finding>) -> usize {
        for finding in findings.iter_mut() {
            if let Some(sev) = self.severity_overrides.get(&finding.rule) {
                if let Some(parsed) = Severity::parse(sev) {
                    finding.severity = parsed;
                }
            }
        }
        let before = findings.len();
        findings.retain(|finding| {
            let disabled = self
                .disable_rules
                .iter()
                .any(|pattern| rule_matches(pattern, &finding.rule));
            if disabled {
                return false;
            }
            let allowed = self.allow.iter().find(|rule| {
                let rule_ok = rule
                    .rule
                    .as_deref()
                    .map(|p| rule_matches(p, &finding.rule))
                    .unwrap_or(true);
                let path_ok = rule
                    .path
                    .as_deref()
                    .map(|p| path_matches(p, &finding.location.path))
                    .unwrap_or(true);
                rule_ok && path_ok
            });
            if let Some(rule) = allowed {
                if let Some(reason) = &rule.reason {
                    tracing::debug!(
                        rule = %finding.rule,
                        path = %finding.location.path,
                        %reason,
                        "allowlisted finding"
                    );
                }
                return false;
            }
            true
        });
        before - findings.len()
    }
}

pub fn config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("DEEPDIVE_CONFIG_DIR") {
        return Some(PathBuf::from(dir));
    }
    directories::ProjectDirs::from("", "", "deepdive").map(|d| d.config_dir().to_path_buf())
}

pub fn cache_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("DEEPDIVE_CACHE_DIR") {
        return Some(PathBuf::from(dir));
    }
    directories::ProjectDirs::from("", "", "deepdive").map(|d| d.cache_dir().to_path_buf())
}

/// Directory for user-supplied detection rules.
pub fn rules_dir() -> Option<PathBuf> {
    config_dir().map(|d| d.join("rules"))
}

/// Wildcard match used for rule ids: `*` matches any sequence, otherwise a prefix
/// such as `secrets` also matches `secrets.aws-access-key`.
pub fn rule_matches(pattern: &str, rule: &str) -> bool {
    if pattern.contains('*') {
        wildcard(pattern, rule)
    } else {
        rule == pattern || rule.starts_with(&format!("{}.", pattern))
    }
}

/// Wildcard/substring match used for paths.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern.contains('*') {
        wildcard(pattern, path)
    } else {
        path.contains(pattern)
    }
}

fn wildcard(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut index = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !value[index..].starts_with(part) {
                return false;
            }
            index += part.len();
        } else if i == parts.len() - 1 {
            if !value[index..].ends_with(part) {
                return false;
            }
            index = value.len();
        } else if let Some(pos) = value[index..].find(part) {
            index += pos + part.len();
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Location;

    fn finding(rule: &str, path: &str) -> Finding {
        Finding {
            id: format!("{}-{}", rule, path),
            severity: Severity::High,
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
    fn matches_rules_and_paths() {
        assert!(rule_matches("secrets", "secrets.aws-access-key"));
        assert!(rule_matches("secrets.*", "secrets.aws-access-key"));
        assert!(!rule_matches("binary", "secrets.aws-access-key"));
        assert!(path_matches("tests/", "/repo/tests/fixture.js"));
        assert!(path_matches("*/fixtures/*", "/repo/tests/fixtures/a.js"));
    }

    #[test]
    fn applies_allowlist_and_overrides() {
        let cfg: ProjectConfig = toml::from_str(
            r#"
disable_rules = ["binary.pe-unsigned"]
severity_overrides = { "dangerous.exec-eval" = "critical" }

[[allow]]
rule = "secrets.*"
path = "tests/"
reason = "test fixtures"
"#,
        )
        .unwrap();
        let mut findings = vec![
            finding("secrets.aws-access-key", "/repo/tests/fixture.js"),
            finding("secrets.aws-access-key", "/repo/src/main.js"),
            finding("binary.pe-unsigned", "/repo/a.exe"),
            finding("dangerous.exec-eval", "/repo/src/main.js"),
        ];
        let suppressed = cfg.apply(&mut findings);
        assert_eq!(suppressed, 2);
        assert_eq!(findings.len(), 2);
        let eval = findings
            .iter()
            .find(|f| f.rule == "dangerous.exec-eval")
            .unwrap();
        assert_eq!(eval.severity, Severity::Critical);
    }
}
