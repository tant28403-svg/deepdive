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
                "dangerous.exec-eval",
                r"(?i)\beval\s*\(",
                Severity::High,
                "Use of eval()",
            ),
            (
                "dangerous.child-process",
                r"(?i)child_process",
                Severity::High,
                "Node child_process module",
            ),
            (
                "dangerous.exec-call",
                r"(?i)\.exec\s*\(",
                Severity::High,
                "exec() call",
            ),
            (
                "dangerous.spawn-call",
                r"(?i)\.spawn\s*\(",
                Severity::Medium,
                "spawn() call",
            ),
            (
                "dangerous.system-call",
                r"(?i)\bsystem\s*\(",
                Severity::High,
                "system() call",
            ),
            (
                "dangerous.os-system",
                r"(?i)os\.system",
                Severity::High,
                "os.system()",
            ),
            (
                "dangerous.subprocess",
                r"(?i)subprocess\.(call|run|Popen|check_output|check_call)",
                Severity::High,
                "subprocess execution",
            ),
            (
                "dangerous.runtime-exec",
                r"(?i)Runtime\.getRuntime\(\)\.exec",
                Severity::Critical,
                "Java Runtime.exec",
            ),
            (
                "dangerous.process-builder",
                r"(?i)ProcessBuilder",
                Severity::High,
                "ProcessBuilder",
            ),
            (
                "dangerous.powershell-iex",
                r"(?i)\bIEX\b|Invoke-Expression",
                Severity::Critical,
                "PowerShell Invoke-Expression",
            ),
            (
                "dangerous.powershell-encoded",
                r"(?i)-enc(?:odedcommand)?\b",
                Severity::Critical,
                "PowerShell encoded command",
            ),
            (
                "dangerous.powershell-download",
                r"(?i)DownloadString|DownloadFile|DownloadData",
                Severity::High,
                "PowerShell download cradle",
            ),
            (
                "dangerous.powershell-hidden",
                r"(?i)-w(?:indowstyle)?\s+hidden|-hidden",
                Severity::Medium,
                "Hidden window style",
            ),
            (
                "dangerous.powershell-b64",
                r"(?i)FromBase64String",
                Severity::High,
                "Base64 decode in PowerShell",
            ),
            (
                "dangerous.lolbin-certutil",
                r"(?i)certutil",
                Severity::Medium,
                "certutil (LOLBin)",
            ),
            (
                "dangerous.lolbin-bitsadmin",
                r"(?i)bitsadmin",
                Severity::Medium,
                "bitsadmin (LOLBin)",
            ),
            (
                "dangerous.lolbin-regsvr32",
                r"(?i)regsvr32",
                Severity::Medium,
                "regsvr32 (LOLBin)",
            ),
            (
                "dangerous.lolbin-rundll32",
                r"(?i)rundll32",
                Severity::Medium,
                "rundll32 (LOLBin)",
            ),
            (
                "dangerous.lolbin-mshta",
                r"(?i)mshta",
                Severity::Medium,
                "mshta (LOLBin)",
            ),
            (
                "dangerous.network-fetch",
                r"(?i)\bfetch\s*\(",
                Severity::Low,
                "fetch() call",
            ),
            (
                "dangerous.network-requests",
                r"(?i)requests\.(get|post|put|delete)",
                Severity::Low,
                "requests HTTP call",
            ),
            (
                "dangerous.network-socket",
                r"(?i)\bsocket\.(socket|connect)",
                Severity::Medium,
                "socket usage",
            ),
            (
                "dangerous.fs-chmod",
                r"(?i)\bchmod\b",
                Severity::Low,
                "chmod",
            ),
            (
                "dangerous.fs-rmtree",
                r"(?i)shutil\.rmtree|rmtree",
                Severity::Medium,
                "recursive delete",
            ),
            (
                "dangerous.base64-decode",
                r"(?i)base64\.b64decode|atob\s*\(|Buffer\.from\([^)]*base64",
                Severity::Medium,
                "Base64 decode",
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
                    confidence: 0.7,
                    rule: rule.id.to_string(),
                    category: "dangerous-api".to_string(),
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
