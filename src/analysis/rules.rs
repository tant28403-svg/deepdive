use crate::types::{Finding, Location, Severity};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub message: String,
}

fn default_severity() -> String {
    "medium".to_string()
}

impl Rule {
    pub fn severity_enum(&self) -> Severity {
        match self.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

pub fn scan_with_rules(path: &Path, content: &str, rules: &[Rule]) -> Vec<Finding> {
    let mut out = Vec::new();
    let path_str = path.display().to_string();
    for rule in rules {
        for pat in &rule.patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                for (i, line) in content.lines().enumerate() {
                    if re.is_match(line) {
                        out.push(Finding {
                            id: format!("rule.{}-{}-{}", rule.name, path_str, i + 1),
                            severity: rule.severity_enum(),
                            confidence: 0.7,
                            rule: rule.name.clone(),
                            category: if rule.category.is_empty() {
                                "custom-rule".to_string()
                            } else {
                                rule.category.clone()
                            },
                            location: Location {
                                path: path_str.clone(),
                                line: Some(i + 1),
                                column: None,
                            },
                            message: if rule.message.is_empty() {
                                format!("Matched rule '{}'", rule.name)
                            } else {
                                rule.message.clone()
                            },
                            snippet: Some(line.trim().to_string()),
                            tags: vec![],
                        });
                    }
                }
            }
        }
    }
    out
}

/// Load rules from a TOML file.
pub fn load_rules_file(path: &Path) -> Vec<Rule> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    if let Ok(rf) = toml::from_str::<RuleFile>(&content) {
        return rf.rules;
    }
    // Allow a bare array or single rule? Try parsing as Vec<Rule>.
    toml::from_str::<Vec<Rule>>(&content).unwrap_or_default()
}
