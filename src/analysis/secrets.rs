use crate::types::{Finding, Location, Severity};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

struct Rule {
    id: &'static str,
    re: Regex,
    severity: Severity,
    message: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let specs: &[(&str, &str, Severity, &str)] = &[
            ("secrets.aws-access-key", r"AKIA[0-9A-Z]{16}", Severity::Critical, "AWS access key ID"),
            ("secrets.aws-secret", r#"(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#, Severity::Critical, "AWS secret access key"),
            ("secrets.github-token", r"gh[pousr]_[A-Za-z0-9]{36,}", Severity::Critical, "GitHub token"),
            ("secrets.github-classic", r"ghp_[A-Za-z0-9]{36}", Severity::Critical, "GitHub personal access token"),
            ("secrets.slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}", Severity::High, "Slack token"),
            ("secrets.stripe-key", r"sk_live_[A-Za-z0-9]{24,}", Severity::Critical, "Stripe live secret key"),
            ("secrets.google-api", r"AIza[0-9A-Za-z\-_]{35}", Severity::High, "Google API key"),
            ("secrets.private-key", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", Severity::Critical, "Private key"),
            ("secrets.jwt", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", Severity::Medium, "JWT token"),
            ("secrets.generic-api-key", r#"(?i)(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]"#, Severity::Medium, "Generic secret assignment"),
        ];
        specs
            .iter()
            .filter_map(|(id, pat, sev, msg)| {
                Regex::new(pat).ok().map(|re| Rule {
                    id,
                    re,
                    severity: *sev,
                    message: msg,
                })
            })
            .collect()
    })
}

pub fn scan(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let path_str = path.display().to_string();
    for (line_no, line) in content.lines().enumerate() {
        for rule in rules() {
            if rule.re.is_match(line) {
                out.push(Finding {
                    id: format!("{}-{}-{}", rule.id, path_str, line_no + 1),
                    severity: rule.severity,
                    confidence: 0.85,
                    rule: rule.id.to_string(),
                    category: "secrets".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: Some(line_no + 1),
                        column: None,
                    },
                    message: rule.message.to_string(),
                    snippet: Some(redact(line.trim())),
                    tags: vec![],
                });
            }
        }
    }
    out
}

fn redact(line: &str) -> String {
    // Truncate long lines to avoid leaking full secrets in output.
    if line.len() > 120 {
        format!("{}...", &line[..120])
    } else {
        line.to_string()
    }
}
