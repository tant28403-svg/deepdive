use crate::types::{Finding, Location, Severity};
use std::path::Path;

pub fn scan(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let path_str = path.display().to_string();

    if name == "package.json" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
            if let Some(scripts) = v.get("scripts").and_then(|s| s.as_object()) {
                for (k, val) in scripts {
                    let cmd = val.as_str().unwrap_or("");
                    let lower = cmd.to_lowercase();
                    let dangerous = k == "preinstall"
                        || k == "install"
                        || k == "postinstall"
                        || lower.contains("curl")
                        || lower.contains("wget")
                        || lower.contains("| sh")
                        || lower.contains("| bash")
                        || lower.contains("eval ")
                        || lower.contains("node -e");
                    if dangerous {
                        let sev = if k == "preinstall" || k == "postinstall" || k == "install" {
                            Severity::High
                        } else {
                            Severity::Medium
                        };
                        out.push(Finding {
                            id: format!("build.npm-script-{}-{}", path_str, k),
                            severity: sev,
                            confidence: 0.8,
                            rule: "build.npm-script".to_string(),
                            category: "build".to_string(),
                            location: Location {
                                path: path_str.clone(),
                                line: None,
                                column: None,
                            },
                            message: format!("npm script '{}' runs: {}", k, cmd),
                            snippet: Some(cmd.to_string()),
                            tags: vec!["npm".to_string()],
                        });
                    }
                }
            }
        }
    }

    // Makefile
    if name == "makefile" || name.ends_with(".mk") {
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.starts_with('\t') || t.starts_with(" ") {
                let lower = t.to_lowercase();
                if lower.contains("curl")
                    || lower.contains("wget")
                    || lower.contains("| sh")
                    || lower.contains("| bash")
                    || lower.contains("rm -rf")
                {
                    out.push(Finding {
                        id: format!("build.makefile-{}-{}", path_str, i + 1),
                        severity: Severity::Medium,
                        confidence: 0.6,
                        rule: "build.makefile-shell".to_string(),
                        category: "build".to_string(),
                        location: Location {
                            path: path_str.clone(),
                            line: Some(i + 1),
                            column: None,
                        },
                        message: "Makefile target runs suspicious shell command".to_string(),
                        snippet: Some(t.to_string()),
                        tags: vec!["make".to_string()],
                    });
                }
            }
        }
    }

    // Dockerfile
    if name == "dockerfile" || name.starts_with("dockerfile.") {
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            let lower = t.to_lowercase();
            if lower.starts_with("from ") && (lower.contains(":latest") || !lower.contains(':')) {
                // informational: latest tag
            }
            if lower.starts_with("user root") || lower == "user root" {
                out.push(Finding {
                    id: format!("build.dockerfile-root-{}-{}", path_str, i + 1),
                    severity: Severity::Medium,
                    confidence: 0.7,
                    rule: "build.dockerfile-root".to_string(),
                    category: "build".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: Some(i + 1),
                        column: None,
                    },
                    message: "Container runs as root".to_string(),
                    snippet: Some(t.to_string()),
                    tags: vec!["docker".to_string()],
                });
            }
            if lower.contains("privileged") || lower.contains("--privileged") {
                out.push(Finding {
                    id: format!("build.dockerfile-privileged-{}-{}", path_str, i + 1),
                    severity: Severity::High,
                    confidence: 0.85,
                    rule: "build.dockerfile-privileged".to_string(),
                    category: "build".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: Some(i + 1),
                        column: None,
                    },
                    message: "Privileged container mode".to_string(),
                    snippet: Some(t.to_string()),
                    tags: vec!["docker".to_string()],
                });
            }
            if (lower.contains("curl") || lower.contains("wget"))
                && (lower.contains("| sh")
                    || lower.contains("| bash")
                    || lower.contains("|sh")
                    || lower.contains("|bash"))
            {
                out.push(Finding {
                    id: format!("build.dockerfile-curlsh-{}-{}", path_str, i + 1),
                    severity: Severity::High,
                    confidence: 0.9,
                    rule: "build.dockerfile-curl-pipe-sh".to_string(),
                    category: "build".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: Some(i + 1),
                        column: None,
                    },
                    message: "curl|sh in Dockerfile".to_string(),
                    snippet: Some(t.to_string()),
                    tags: vec!["docker".to_string()],
                });
            }
            if lower.contains("/var/run/docker.sock") {
                out.push(Finding {
                    id: format!("build.dockerfile-dockersock-{}-{}", path_str, i + 1),
                    severity: Severity::High,
                    confidence: 0.85,
                    rule: "build.dockerfile-docker-socket".to_string(),
                    category: "build".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: Some(i + 1),
                        column: None,
                    },
                    message: "Docker socket mounted (container escape risk)".to_string(),
                    snippet: Some(t.to_string()),
                    tags: vec!["docker".to_string()],
                });
            }
        }
    }

    // GitHub Actions workflows
    let is_workflow = path_str.contains(".github")
        && path_str.contains("workflows")
        && (name.ends_with(".yml") || name.ends_with(".yaml"));
    if is_workflow {
        // scan run: lines
        let mut in_run = false;
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            let t2 = t.trim_start_matches("- ").trim();
            if t2.starts_with("run:") || t2.starts_with("run: |") {
                in_run = true;
                let cmd = t2
                    .trim_start_matches("run:")
                    .trim()
                    .trim_start_matches('|')
                    .trim();
                if !cmd.is_empty() {
                    check_shell_cmd(path_str.clone(), i + 1, cmd, &mut out, "ci");
                }
                continue;
            }
            if in_run && (line.starts_with(' ') || line.starts_with('\t')) && !t.is_empty() {
                check_shell_cmd(path_str.clone(), i + 1, t, &mut out, "ci");
                continue;
            }
            in_run = false;
            // secrets in env
            let lower = t.to_lowercase();
            if lower.contains("password:") || lower.contains("token:") || lower.contains("secret:")
            {
                // informational only if hardcoded value
                if t.contains(": ") && !t.contains("${{") {
                    out.push(Finding {
                        id: format!("build.ci-secret-{}-{}", path_str, i + 1),
                        severity: Severity::High,
                        confidence: 0.7,
                        rule: "build.ci-hardcoded-secret".to_string(),
                        category: "build".to_string(),
                        location: Location {
                            path: path_str.clone(),
                            line: Some(i + 1),
                            column: None,
                        },
                        message: "Possible hardcoded secret in CI workflow".to_string(),
                        snippet: Some(t.to_string()),
                        tags: vec!["ci".to_string()],
                    });
                }
            }
        }
    }

    // setup.py / pyproject
    if name == "setup.py" {
        for (i, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            if lower.contains("os.system")
                || lower.contains("subprocess")
                || lower.contains("exec(")
                || lower.contains("eval(")
            {
                out.push(Finding {
                    id: format!("build.setuppy-{}-{}", path_str, i + 1),
                    severity: Severity::High,
                    confidence: 0.8,
                    rule: "build.setuppy-exec".to_string(),
                    category: "build".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: Some(i + 1),
                        column: None,
                    },
                    message: "setup.py runs code during install".to_string(),
                    snippet: Some(line.trim().to_string()),
                    tags: vec!["python".to_string()],
                });
            }
        }
    }

    out
}

fn check_shell_cmd(path_str: String, line: usize, cmd: &str, out: &mut Vec<Finding>, tag: &str) {
    let lower = cmd.to_lowercase();
    let suspicious = lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("| sh")
        || lower.contains("| bash")
        || lower.contains("eval ")
        || lower.contains("base64");
    if suspicious {
        out.push(Finding {
            id: format!("build.{}-shell-{}-{}", tag, path_str, line),
            severity: Severity::Medium,
            confidence: 0.7,
            rule: "build.shell-command".to_string(),
            category: "build".to_string(),
            location: Location {
                path: path_str,
                line: Some(line),
                column: None,
            },
            message: "CI/build runs suspicious shell command".to_string(),
            snippet: Some(cmd.to_string()),
            tags: vec![tag.to_string()],
        });
    }
}
