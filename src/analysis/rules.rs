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

/// Rule ids implemented natively by the built-in detectors.
pub fn builtin_rule_ids() -> &'static [&'static str] {
    &[
        "ast.js-tainted-sink",
        "ast.py-tainted-sink",
        "dangerous.exec-eval",
        "dangerous.child-process",
        "dangerous.exec-call",
        "dangerous.spawn-call",
        "dangerous.system-call",
        "dangerous.os-system",
        "dangerous.subprocess",
        "dangerous.runtime-exec",
        "dangerous.process-builder",
        "dangerous.powershell-iex",
        "dangerous.powershell-encoded",
        "dangerous.powershell-download",
        "dangerous.powershell-hidden",
        "dangerous.powershell-b64",
        "dangerous.lolbin-certutil",
        "dangerous.lolbin-bitsadmin",
        "dangerous.lolbin-regsvr32",
        "dangerous.lolbin-rundll32",
        "dangerous.lolbin-mshta",
        "dangerous.network-fetch",
        "dangerous.network-requests",
        "dangerous.network-socket",
        "dangerous.fs-chmod",
        "dangerous.fs-rmtree",
        "dangerous.base64-decode",
        "secrets.aws-access-key",
        "secrets.aws-secret",
        "secrets.github-token",
        "secrets.github-classic",
        "secrets.slack-token",
        "secrets.stripe-key",
        "secrets.google-api",
        "secrets.private-key",
        "secrets.jwt",
        "secrets.generic-api-key",
        "binary.pe-wx-section",
        "binary.pe-high-entropy",
        "binary.pe-packer",
        "binary.pe-dangerous-imports",
        "binary.pe-overlay",
        "binary.pe-unsigned",
        "binary.pe-embedded",
        "binary.pe-masquerade-system",
        "binary.pe-version-mismatch",
        "binary.pe-microsoft-in-temp",
        "binary.elf-rwx-segment",
        "binary.elf-dangerous-symbol",
        "binary.elf-high-entropy",
        "binary.elf-temp-interpreter",
        "binary.elf-relative-rpath",
        "binary.macho-wx-segment",
        "binary.macho-untrusted-dylib",
        "binary.macho-relative-rpath",
        "binary.strings-powershell",
        "binary.strings-urls",
        "binary.strings-registry",
        "binary.strings-ips",
        "binary.strings-base64",
        "archive.path-traversal",
        "archive.symlink-escape",
        "archive.zip-bomb",
        "archive.depth-exceeded",
        "archive.size-limit",
        "archive.entry-too-large",
        "archive.nested",
        "archive.unsupported-format",
        "windows.lnk-remote-target",
        "windows.lnk-suspicious-arguments",
        "windows.lnk-suspicious-command",
        "windows.lnk-script-target",
        "windows.reg-persistence",
        "windows.reg-persistence-value",
        "windows.reg-suspicious-value",
        "windows.msi-custom-action",
        "windows.task-suspicious-action",
        "windows.task-action",
        "windows.ads-hidden-stream",
        "windows.reparse-point",
        "symlink.absolute-escape",
        "symlink.path-escape",
        "symlink.broken",
        "doc.pdf-active-content",
        "doc.office-vba-macro",
        "doc.office-dde",
        "doc.office-remote-template",
        "doc.office-external-link",
        "doc.html-inline-script",
        "doc.html-eval",
        "doc.notebook-shell-escape",
        "build.npm-script",
        "build.makefile-shell",
        "build.dockerfile-root",
        "build.dockerfile-privileged",
        "build.dockerfile-curl-pipe-sh",
        "build.dockerfile-docker-socket",
        "build.ci-hardcoded-secret",
        "build.shell-command",
        "build.setuppy-exec",
        "config.insecure-tls",
        "config.debug-enabled",
        "config.npm-insecure-registry",
        "config.ci-remote-include",
        "config.ci-unpinned-image",
        "config.ci-shell-command",
        "config.ci-remote-script",
        "config.composer-install-hook",
        "config.composer-insecure-http",
        "config.composer-insecure-repository",
        "config.gemfile-insecure-source",
        "config.gemfile-insecure-git",
        "config.gemfile-dynamic-code",
        "config.gemfile-shell-command",
        "config.pipfile-insecure-source",
        "config.pipfile-script",
        "config.kubernetes-privileged",
        "config.kubernetes-host-namespace",
        "config.kubernetes-hostpath",
        "config.kubernetes-root",
        "config.kubernetes-privilege-escalation",
        "config.kubernetes-dangerous-capability",
        "config.kubernetes-unpinned-image",
        "config.kubernetes-cluster-admin",
        "config.terraform-open-ingress",
        "config.terraform-public-resource",
        "config.terraform-unencrypted",
        "config.terraform-unsafe-lifecycle",
        "config.terraform-insecure-provider",
        "config.terraform-wildcard-iam",
        "deps.known-vulnerability",
        "deps.typosquatting",
        "deps.invalid-lockfile",
        "deps.lockfile-outdated",
        "deps.lockfile-missing-integrity",
        "deps.tampered-integrity",
        "deps.insecure-resolution",
        "deps.unpinned-git-dependency",
        "deps.insecure-registry",
        "deps.registry-missing-auth",
        "deps.dependency-confusion",
        "deps.manifest-drift",
    ]
}

/// Compile every pattern and report invalid rules.
pub fn validate_rules(rules: &[Rule]) -> Vec<String> {
    let mut errors = Vec::new();
    for rule in rules {
        if rule.patterns.is_empty() {
            errors.push(format!("rule '{}' has no patterns", rule.name));
        }
        for pattern in &rule.patterns {
            if let Err(err) = regex::Regex::new(pattern) {
                errors.push(format!(
                    "rule '{}': invalid pattern '{}': {}",
                    rule.name, pattern, err
                ));
            }
        }
    }
    errors
}
