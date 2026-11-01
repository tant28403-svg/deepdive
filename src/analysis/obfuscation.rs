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
            (
                "obfuscation.eval-base64",
                r"(?i)eval\s*\(\s*(atob|Buffer\.from|base64)",
                Severity::Critical,
                "eval of decoded payload",
            ),
            (
                "obfuscation.fromcharcode",
                r"(?i)fromCharCode",
                Severity::High,
                "Character-code reconstruction",
            ),
            (
                "obfuscation.string-concat",
                r"(?i)String\.fromCharCode",
                Severity::High,
                "String reconstruction",
            ),
            (
                "obfuscation.hex-escape",
                r"(\\x[0-9a-fA-F]{2}){6,}",
                Severity::Medium,
                "Long hex escape sequence",
            ),
            (
                "obfuscation.unicode-escape",
                r"(\\u[0-9a-fA-F]{4}){6,}",
                Severity::Medium,
                "Long unicode escape sequence",
            ),
            (
                "obfuscation.jsfuck",
                r"(\[\]\[\]\+)+",
                Severity::High,
                "JSFuck-style obfuscation",
            ),
            (
                "obfuscation.python-exec-decode",
                r"(?i)exec\s*\(\s*(base64|codecs|marshal|pickle)",
                Severity::Critical,
                "exec of decoded payload",
            ),
            (
                "obfuscation.python-compile",
                r"(?i)compile\s*\(",
                Severity::Medium,
                "Dynamic compile()",
            ),
            (
                "obfuscation.powershell-iex-b64",
                r"(?i)IEX.*FromBase64String|FromBase64String.*IEX",
                Severity::Critical,
                "IEX of base64 payload",
            ),
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
                    confidence: 0.75,
                    rule: rule.id.to_string(),
                    category: "obfuscation".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: Some(line_no + 1),
                        column: None,
                    },
                    message: rule.message.to_string(),
                    snippet: Some(line.trim().to_string()),
                    tags: vec![],
                });
            }
        }
    }
    out
}
