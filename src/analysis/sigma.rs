use crate::types::{Finding, Location, Severity};
use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use std::collections::BTreeMap;
use std::path::Path;

/// A Sigma rule reduced to its static content-matching form.
///
/// Sigma is designed for event logs, not file contents. deepdive evaluates the
/// detection selectors against file lines so a dropped Sigma rule can still
/// catch known command lines and script artifacts without a log pipeline.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub level: Severity,
    pub tags: Vec<String>,
    pub condition: String,
    selectors: BTreeMap<String, Vec<FieldMatcher>>,
}

#[derive(Debug, Clone)]
struct FieldMatcher {
    patterns: Vec<Regex>,
    require_all: bool,
}

#[derive(Debug, Clone)]
pub struct Match {
    pub line: usize,
    pub snippet: String,
}

impl SigmaRule {
    /// Evaluate the rule against a text buffer.
    pub fn matches(&self, content: &str) -> Option<Match> {
        if self.selectors.is_empty() {
            return None;
        }
        let mut selector_hits: BTreeMap<&str, bool> = BTreeMap::new();
        let mut first_line: Option<Match> = None;

        for (i, line) in content.lines().enumerate() {
            for (name, matchers) in &self.selectors {
                let hit = matchers.iter().all(|matcher| {
                    let matched = matcher
                        .patterns
                        .iter()
                        .filter(|re| re.is_match(line))
                        .count();
                    if matcher.require_all {
                        matched == matcher.patterns.len()
                    } else {
                        matched > 0
                    }
                });
                if hit {
                    selector_hits.insert(name.as_str(), true);
                    if first_line.is_none() && line.trim().len() > 3 {
                        first_line = Some(Match {
                            line: i + 1,
                            snippet: line.trim().chars().take(200).collect(),
                        });
                    }
                }
            }
        }

        if self.evaluate(&self.condition, &selector_hits) {
            Some(first_line.unwrap_or(Match {
                line: 0,
                snippet: String::new(),
            }))
        } else {
            None
        }
    }

    fn evaluate(&self, condition: &str, hits: &BTreeMap<&str, bool>) -> bool {
        let condition = trim_parens(condition.trim());
        if condition.is_empty() {
            return false;
        }
        if let Some((left, right)) = split_operator(condition, " or ") {
            return self.evaluate(left, hits) || self.evaluate(right, hits);
        }
        if let Some((left, right)) = split_operator(condition, " and ") {
            return self.evaluate(left, hits) && self.evaluate(right, hits);
        }
        if let Some(rest) = condition.strip_prefix("not ") {
            return !self.evaluate(rest, hits);
        }
        if let Some((quantifier, target)) = condition.split_once(" of ") {
            let target = trim_parens(target.trim());
            let names: Vec<&str> = if target == "them" {
                self.selectors.keys().map(|s| s.as_str()).collect()
            } else {
                self.selectors
                    .keys()
                    .filter(|name| wildcard(target, name))
                    .map(|s| s.as_str())
                    .collect()
            };
            let matched = names
                .iter()
                .filter(|name| hits.get(**name).copied().unwrap_or(false))
                .count();
            return match quantifier.trim().to_lowercase().as_str() {
                "all" => !names.is_empty() && matched == names.len(),
                "1" | "any" => matched >= 1,
                other => other
                    .parse::<usize>()
                    .map(|n| matched >= n)
                    .unwrap_or(false),
            };
        }
        hits.get(condition).copied().unwrap_or(false)
    }
}

fn trim_parens(mut value: &str) -> &str {
    loop {
        if !value.starts_with('(') || !value.ends_with(')') {
            return value;
        }
        let mut depth = 0i32;
        let mut closes_at_end = false;
        for (i, c) in value.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        closes_at_end = i == value.len() - 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !closes_at_end {
            return value;
        }
        value = &value[1..value.len() - 1];
    }
}

fn split_operator<'a>(value: &'a str, operator: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0i32;
    let bytes = value.as_bytes();
    let op = operator.as_bytes();
    let mut i = 0usize;
    while i + op.len() <= bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && &bytes[i..i + op.len()] == op {
            let left = value[..i].trim();
            let right = value[i + op.len()..].trim();
            if !left.is_empty() && !right.is_empty() {
                return Some((left, right));
            }
        }
        i += 1;
    }
    None
}

fn wildcard(pattern: &str, value: &str) -> bool {
    let regex = format!(
        "^{}$",
        regex::escape(pattern)
            .replace(r"\*", ".*")
            .replace(r"\?", ".")
    );
    Regex::new(&regex)
        .map(|re| re.is_match(value))
        .unwrap_or(false)
}

fn build_pattern(value: &str, modifiers: &[String]) -> Option<Regex> {
    let re_mode = modifiers.iter().any(|m| m == "re");
    let contains = modifiers.iter().any(|m| m == "contains");
    let startswith = modifiers.iter().any(|m| m == "startswith");
    let endswith = modifiers.iter().any(|m| m == "endswith");
    if re_mode {
        return RegexBuilder::new(value).case_insensitive(true).build().ok();
    }
    let mut escaped = regex::escape(value)
        .replace(r"\*", ".*")
        .replace(r"\?", ".");
    if contains {
        escaped = format!(".*{}.*", escaped);
    } else if startswith {
        escaped = format!("^{}", escaped);
    } else if endswith {
        escaped = format!("{}$", escaped);
    }
    RegexBuilder::new(&escaped)
        .case_insensitive(true)
        .build()
        .ok()
}

fn value_strings(value: &serde_yaml::Value, out: &mut Vec<String>) {
    match value {
        serde_yaml::Value::String(s) => out.push(s.clone()),
        serde_yaml::Value::Number(n) => out.push(n.to_string()),
        serde_yaml::Value::Bool(b) => out.push(b.to_string()),
        serde_yaml::Value::Sequence(values) => {
            for v in values {
                value_strings(v, out);
            }
        }
        _ => {}
    }
}

fn parse_selector(value: &serde_yaml::Value) -> Option<Vec<FieldMatcher>> {
    match value {
        serde_yaml::Value::Mapping(map) => {
            let mut matchers = Vec::new();
            for (key, value) in map {
                let Some(key) = key.as_str() else {
                    continue;
                };
                let mut parts = key.split('|');
                let _field = parts.next().unwrap_or("keywords");
                let modifiers: Vec<String> = parts.map(|m| m.to_lowercase()).collect();
                let mut values = Vec::new();
                value_strings(value, &mut values);
                let patterns: Vec<Regex> = values
                    .iter()
                    .filter_map(|v| build_pattern(v, &modifiers))
                    .collect();
                if patterns.is_empty() {
                    continue;
                }
                matchers.push(FieldMatcher {
                    patterns,
                    require_all: modifiers.iter().any(|m| m == "all"),
                });
            }
            if matchers.is_empty() {
                None
            } else {
                Some(matchers)
            }
        }
        serde_yaml::Value::Sequence(_) | serde_yaml::Value::String(_) => {
            let mut values = Vec::new();
            value_strings(value, &mut values);
            let patterns: Vec<Regex> = values
                .iter()
                .filter_map(|v| build_pattern(v, &[]))
                .collect();
            if patterns.is_empty() {
                None
            } else {
                Some(vec![FieldMatcher {
                    patterns,
                    require_all: false,
                }])
            }
        }
        _ => None,
    }
}

fn parse_rule(value: &serde_yaml::Value) -> Option<SigmaRule> {
    let map = value.as_mapping()?;
    let detection = map.get(serde_yaml::Value::String("detection".to_string()))?;
    let detection = detection.as_mapping()?;
    let mut selectors = BTreeMap::new();
    for (key, value) in detection {
        let Some(key) = key.as_str() else {
            continue;
        };
        if key == "condition" || key == "timeframe" {
            continue;
        }
        if let Some(selectors_for_name) = parse_selector(value) {
            selectors.insert(key.to_string(), selectors_for_name);
        }
    }
    if selectors.is_empty() {
        return None;
    }

    let get_str = |key: &str| {
        map.get(serde_yaml::Value::String(key.to_string()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let title = get_str("title").unwrap_or_else(|| "Untitled Sigma rule".to_string());
    let id = get_str("id")
        .or_else(|| {
            get_str("title").map(|t| {
                t.to_lowercase()
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c } else { '-' })
                    .collect::<String>()
                    .trim_matches('-')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "unnamed".to_string());
    let level = get_str("level")
        .as_deref()
        .and_then(Severity::parse)
        .unwrap_or(Severity::High);
    let description = get_str("description").unwrap_or_default();
    let condition = detection
        .get(serde_yaml::Value::String("condition".to_string()))
        .and_then(|v| v.as_str())
        .unwrap_or("selection")
        .to_string();
    let tags = map
        .get(serde_yaml::Value::String("tags".to_string()))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Some(SigmaRule {
        id,
        title,
        description,
        level,
        tags,
        condition,
        selectors,
    })
}

fn parse_document(value: &serde_yaml::Value, out: &mut Vec<SigmaRule>) {
    match value {
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                parse_document(item, out);
            }
        }
        serde_yaml::Value::Mapping(_) => {
            if let Some(rule) = parse_rule(value) {
                out.push(rule);
            }
        }
        _ => {}
    }
}

/// Load one or more Sigma rules from a YAML file.
pub fn load_file(path: &Path) -> Result<Vec<SigmaRule>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read Sigma rule {}", path.display()))?;
    let mut rules = Vec::new();
    for document in serde_yaml::Deserializer::from_str(&content) {
        let value = serde_yaml::Value::deserialize(document)
            .with_context(|| format!("parse Sigma YAML {}", path.display()))?;
        parse_document(&value, &mut rules);
    }
    Ok(rules)
}

/// Scan text with the supplied Sigma rules.
pub fn scan(path: &Path, content: &str, rules: &[SigmaRule]) -> Vec<Finding> {
    let path_str = path.display().to_string();
    let mut out = Vec::new();
    for rule in rules {
        let Some(hit) = rule.matches(content) else {
            continue;
        };
        let mut tags = vec!["sigma".to_string()];
        tags.extend(rule.tags.iter().cloned());
        out.push(Finding {
            id: format!("sigma.{}-{}", rule.id, path_str),
            severity: rule.level,
            confidence: 0.75,
            rule: format!("sigma.{}", rule.id),
            category: "sigma".to_string(),
            location: Location {
                path: path_str.clone(),
                line: if hit.line == 0 { None } else { Some(hit.line) },
                column: None,
            },
            message: if rule.description.is_empty() {
                format!("Sigma rule matched: {}", rule.title)
            } else {
                format!("Sigma rule matched: {} — {}", rule.title, rule.description)
            },
            snippet: if hit.snippet.is_empty() {
                None
            } else {
                Some(hit.snippet)
            },
            tags,
        });
    }
    out
}

use serde::Deserialize;

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"
title: Encoded PowerShell
id: test-encoded-powershell
level: critical
tags:
  - attack.execution
detection:
  selection:
    CommandLine|contains|all:
      - powershell
      - '-enc'
  filter:
    CommandLine|contains: 'benign'
  condition: selection and not filter
"#;

    #[test]
    fn parses_and_matches_a_rule() {
        let rules = load_file_from_str(RULE);
        assert_eq!(rules.len(), 1);
        let hit = rules[0]
            .matches("powershell.exe -w hidden -enc SQBFAFgA")
            .unwrap();
        assert_eq!(hit.line, 1);
        assert!(rules[0].matches("powershell benign").is_none());
    }

    #[test]
    fn supports_quantified_conditions() {
        let rules = load_file_from_str(RULE);
        assert!(rules[0].condition.contains("and not"));
    }

    fn load_file_from_str(content: &str) -> Vec<SigmaRule> {
        let value = serde_yaml::from_str::<serde_yaml::Value>(content).unwrap();
        let mut rules = Vec::new();
        parse_document(&value, &mut rules);
        rules
    }
}
