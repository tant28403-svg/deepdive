use crate::types::{Finding, Location, Severity};
use std::path::Path;

fn finding(
    path: &Path,
    rule: &str,
    severity: Severity,
    message: String,
    snippet: Option<String>,
    tags: &[&str],
) -> Finding {
    Finding {
        id: format!("{}-{}", rule, path.display()),
        severity,
        confidence: 0.75,
        rule: rule.to_string(),
        category: "windows".to_string(),
        location: Location {
            path: path.display().to_string(),
            line: None,
            column: None,
        },
        message,
        snippet,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    }
}

const LOLBINS: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "msiexec",
    "schtasks",
    "wmic",
    "curl",
    "wget",
];

/// Extract printable ASCII strings (length >= 4).
fn ascii_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            current.push(b as char);
        } else {
            if current.len() >= 4 {
                out.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if current.len() >= 4 {
        out.push(current);
    }
    out
}

/// Extract printable UTF-16LE strings (length >= 4).
fn utf16_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if let Some(c) = char::from_u32(unit as u32) {
            if !c.is_control() && !c.is_whitespace() {
                current.push(c);
                continue;
            }
        }
        if current.len() >= 4 {
            out.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if current.len() >= 4 {
        out.push(current);
    }
    out
}

pub(crate) fn all_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = ascii_strings(bytes);
    out.extend(utf16_strings(bytes));
    out
}

/// Describe suspicious command constructs inside a string.
fn suspicious_reasons(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    let mut reasons = Vec::new();
    let has_lolbin = LOLBINS.iter().any(|b| lower.contains(b));
    if has_lolbin {
        reasons.push("references a living-off-the-land binary");
    }
    if lower.contains("-enc")
        || lower.contains("-encodedcommand")
        || lower.contains("frombase64string")
    {
        reasons.push("uses an encoded command");
    }
    if lower.contains("-w hidden")
        || lower.contains("-windowstyle hidden")
        || lower.contains("hidden")
    {
        reasons.push("requests a hidden window");
    }
    if lower.contains("invoke-expression")
        || lower.contains("iex ")
        || lower.contains("downloadstring")
        || lower.contains("downloadfile")
        || lower.contains("net.webclient")
    {
        reasons.push("downloads or evaluates remote content");
    }
    if lower.contains("http://") || lower.contains("https://") {
        reasons.push("contains a URL");
    }
    if lower.contains("%temp%") || lower.contains("\\appdata\\") || lower.contains("/tmp/") {
        reasons.push("writes to a temporary/user-writable path");
    }
    if lower.contains("scrobj.dll") || lower.contains("javascript:") || lower.contains("vbscript:")
    {
        reasons.push("uses a scriptlet/script moniker");
    }
    reasons
}

fn scan_lnk(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let strings = all_strings(bytes);

    // Remote or UNC targets.
    for s in &strings {
        let lower = s.to_lowercase();
        if (lower.starts_with("\\\\") || lower.contains("http://") || lower.contains("https://"))
            && s.len() > 6
        {
            out.push(finding(
                path,
                "windows.lnk-remote-target",
                Severity::High,
                format!("Shortcut points to a remote target: {}", truncate(s)),
                Some(truncate(s)),
                &["lnk", "remote"],
            ));
            break;
        }
    }

    // Dangerous interpreter targets.
    for s in &strings {
        let lower = s.to_lowercase();
        if ["powershell", "pwsh", "wscript", "cscript", "mshta", "cmd"]
            .iter()
            .any(|b| lower.contains(b))
            && !suspicious_reasons(s).is_empty()
        {
            out.push(finding(
                path,
                "windows.lnk-suspicious-arguments",
                Severity::Critical,
                format!(
                    "Shortcut invokes '{}': {}",
                    truncate(s),
                    suspicious_reasons(s).join(", ")
                ),
                Some(truncate(s)),
                &["lnk", "command"],
            ));
            continue;
        }
        for &re in &suspicious_reasons(s) {
            if re == "uses an encoded command"
                || re == "downloads or evaluates remote content"
                || re == "uses a scriptlet/script moniker"
            {
                out.push(finding(
                    path,
                    "windows.lnk-suspicious-command",
                    Severity::High,
                    format!("Shortcut command {}", re),
                    Some(truncate(s)),
                    &["lnk", "command"],
                ));
                break;
            }
        }
    }

    // Script/binary payload extensions.
    for s in &strings {
        let lower = s.to_lowercase();
        if [
            ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta", ".scr",
        ]
        .iter()
        .any(|e| lower.ends_with(e) || lower.contains(&format!("{e} ")))
        {
            out.push(finding(
                path,
                "windows.lnk-script-target",
                Severity::Medium,
                format!("Shortcut targets a script payload: {}", truncate(s)),
                Some(truncate(s)),
                &["lnk", "script"],
            ));
            break;
        }
    }
    dedup(out)
}

fn scan_reg(path: &Path, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let persistence_keys = [
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\currentversion\\policies\\explorer\\run",
        "\\winlogon",
        "image file execution options",
        "appinit_dlls",
        "\\services\\",
        "\\currentversion\\shell service object delayload",
        "\\currentversion\\explorer\\browser helper objects",
    ];
    let mut in_persistence_section = false;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        let lower = trimmed.to_lowercase();
        let reasons = suspicious_reasons(trimmed);

        // A new registry key section starts with '['.
        if trimmed.starts_with('[') {
            in_persistence_section = persistence_keys.iter().any(|k| lower.contains(k));
            if in_persistence_section {
                out.push(Finding {
                    id: format!("windows.reg-persistence-{}-{}", path.display(), i + 1),
                    severity: Severity::Medium,
                    confidence: 0.8,
                    rule: "windows.reg-persistence".to_string(),
                    category: "windows".to_string(),
                    location: Location {
                        path: path.display().to_string(),
                        line: Some(i + 1),
                        column: None,
                    },
                    message: "Registry export writes an autostart/persistence key".to_string(),
                    snippet: Some(truncate(trimmed)),
                    tags: vec!["reg".to_string(), "persistence".to_string()],
                });
            }
            continue;
        }

        if in_persistence_section && !reasons.is_empty() {
            out.push(Finding {
                id: format!("windows.reg-persistence-value-{}-{}", path.display(), i + 1),
                severity: Severity::Critical,
                confidence: 0.85,
                rule: "windows.reg-persistence-value".to_string(),
                category: "windows".to_string(),
                location: Location {
                    path: path.display().to_string(),
                    line: Some(i + 1),
                    column: None,
                },
                message: format!(
                    "Persistence entry runs a suspicious command: {}",
                    reasons.join(", ")
                ),
                snippet: Some(truncate(trimmed)),
                tags: vec!["reg".to_string(), "persistence".to_string()],
            });
        } else if !in_persistence_section && reasons.len() >= 2 {
            out.push(Finding {
                id: format!("windows.reg-suspicious-{}-{}", path.display(), i + 1),
                severity: Severity::Medium,
                confidence: 0.7,
                rule: "windows.reg-suspicious-value".to_string(),
                category: "windows".to_string(),
                location: Location {
                    path: path.display().to_string(),
                    line: Some(i + 1),
                    column: None,
                },
                message: format!("Suspicious registry value: {}", reasons.join(", ")),
                snippet: Some(truncate(trimmed)),
                tags: vec!["reg".to_string()],
            });
        }
    }
    out
}

fn scan_msi(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let strings = all_strings(bytes);
    let mut hits: Vec<String> = Vec::new();
    for s in &strings {
        let lower = s.to_lowercase();
        if lower.contains("customaction")
            || lower.contains("jscript")
            || lower.contains("vbscript")
            || lower.contains("activexobject")
            || (lower.contains("powershell") && !suspicious_reasons(s).is_empty())
            || lower.contains("scrobj.dll")
        {
            hits.push(truncate(s));
        }
    }
    hits.sort();
    hits.dedup();
    if !hits.is_empty() {
        out.push(finding(
            path,
            "windows.msi-custom-action",
            Severity::High,
            format!(
                "MSI contains scriptable custom actions or hidden commands ({} candidate strings)",
                hits.len()
            ),
            Some(hits.join(" | ")),
            &["msi", "installer"],
        ));
    }
    dedup(out)
}

fn extract_tag(text: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        out.push(after[..end].trim().to_string());
        rest = &after[end + close.len()..];
    }
    out
}

fn scan_task_xml(path: &Path, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let commands = extract_tag(text, "Command");
    let arguments = extract_tag(text, "Arguments");
    let mut combined = commands.clone();
    combined.extend(arguments.clone());
    let command_line = combined.join(" ");
    let reasons = suspicious_reasons(&command_line);
    let has_url = command_line.to_lowercase().contains("http");
    let has_lolbin = LOLBINS
        .iter()
        .any(|b| command_line.to_lowercase().contains(b));

    if has_url || has_lolbin || reasons.len() >= 2 {
        let severity = if reasons.iter().any(|r| {
            *r == "uses an encoded command"
                || *r == "downloads or evaluates remote content"
                || *r == "uses a scriptlet/script moniker"
        }) {
            Severity::Critical
        } else {
            Severity::High
        };
        out.push(finding(
            path,
            "windows.task-suspicious-action",
            severity,
            format!(
                "Scheduled task runs a suspicious action ({}): {}",
                if reasons.is_empty() {
                    "LOLBin/URL".to_string()
                } else {
                    reasons.join(", ")
                },
                truncate(&command_line)
            ),
            Some(truncate(&command_line)),
            &["scheduled-task", "persistence"],
        ));
    } else if !commands.is_empty() {
        out.push(finding(
            path,
            "windows.task-action",
            Severity::Info,
            format!("Scheduled task action: {}", truncate(&command_line)),
            Some(truncate(&command_line)),
            &["scheduled-task"],
        ));
    }
    out
}

fn truncate(s: &str) -> String {
    s.chars().take(200).collect()
}

fn dedup(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    findings
        .into_iter()
        .filter(|f| {
            seen.insert(format!(
                "{}|{}",
                f.rule,
                f.snippet.clone().unwrap_or_default()
            ))
        })
        .collect()
}

fn looks_like_task_xml(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("<task ") && lower.contains("schemas.microsoft.com/windows/2004/02/mit/task")
}

/// Analyse a Windows artifact by extension and content.
pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let text = std::str::from_utf8(bytes).ok();

    if name.ends_with(".lnk") || (bytes.len() >= 8 && bytes[0..4] == [0x4C, 0x00, 0x00, 0x00]) {
        return scan_lnk(path, bytes);
    }
    if name.ends_with(".reg") || text.is_some_and(|t| t.starts_with("REGEDIT4")) {
        return scan_reg(path, text.unwrap_or(""));
    }
    if name.ends_with(".msi") || name.ends_with(".msp") || name.ends_with(".mst") {
        return scan_msi(path, bytes);
    }
    if let Some(t) = text {
        if looks_like_task_xml(t) {
            return scan_task_xml(path, t);
        }
    }
    Vec::new()
}

/// Enumerate alternate data streams and reparse points on Windows.
pub fn scan_tree(root: &Path) -> Vec<Finding> {
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        let walker = ignore::WalkBuilder::new(root)
            .hidden(false)
            .git_ignore(true)
            .git_global(false)
            .follow_links(false)
            .build();
        for (i, entry) in walker.flatten().enumerate() {
            if i > 20_000 {
                break;
            }
            let path = entry.path();
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            out.extend(streams_for(path));
            out.extend(reparse_for(path));
        }
        out
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        Vec::new()
    }
}

#[cfg(windows)]
fn streams_for(path: &Path) -> Vec<Finding> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        WIN32_FIND_STREAM_DATA,
    };

    let mut out = Vec::new();
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    let Ok(handle) = (unsafe {
        FindFirstStreamW(
            windows::core::PCWSTR(wide.as_ptr()),
            FindStreamInfoStandard,
            &mut data as *mut _ as *mut c_void,
            0,
        )
    }) else {
        return out;
    };

    loop {
        let name = String::from_utf16_lossy(&data.cStreamName);
        let name = name.trim_end_matches('\0');
        // Every file exposes the unnamed default data stream; ignore it.
        if name == "::$DATA" || name == ":$DATA" {
            let more = unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut c_void) };
            if more.is_err() {
                break;
            }
            continue;
        }
        let stream = name
            .trim_start_matches(':')
            .split(":$DATA")
            .next()
            .unwrap_or("")
            .to_string();
        if !stream.is_empty() {
            out.push(finding(
                path,
                "windows.ads-hidden-stream",
                Severity::High,
                format!(
                    "Alternate data stream '{}' found ({} bytes) — hidden content",
                    stream, data.StreamSize
                ),
                Some(name.to_string()),
                &["ads", "hidden"],
            ));
        }
        let more = unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut c_void) };
        if more.is_err() {
            break;
        }
    }
    unsafe {
        let _ = FindClose(handle);
    }
    out
}

#[cfg(windows)]
fn reparse_for(path: &Path) -> Vec<Finding> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Vec::new();
    };
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 && !meta.file_type().is_symlink()
    {
        return vec![finding(
            path,
            "windows.reparse-point",
            Severity::Medium,
            "Reparse point (junction/mount point) redirects filesystem access".to_string(),
            None,
            &["reparse", "junction"],
        )];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_registry_persistence() {
        let text = "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Updater\"=\"powershell -w hidden -enc SQBFAFgA\"\n";
        let findings = scan(Path::new("autorun.reg"), text.as_bytes());
        assert!(findings.iter().any(|f| f.rule == "windows.reg-persistence"));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn flags_scheduled_task_encoded_powershell() {
        let xml = r#"<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc SQBFAFgA</Arguments></Exec></Actions>
</Task>"#;
        let findings = scan(Path::new("task.xml"), xml.as_bytes());
        assert!(findings
            .iter()
            .any(|f| f.rule == "windows.task-suspicious-action"));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn flags_lnk_with_encoded_command() {
        let mut bytes = vec![0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
        bytes.extend_from_slice(&[0u8; 64]);
        for unit in "powershell.exe -w hidden -enc SQBFAFgA".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let findings = scan(Path::new("shortcut.lnk"), &bytes);
        assert!(findings.iter().any(|f| f.rule.contains("lnk")));
    }

    #[test]
    fn flags_msi_custom_action_strings() {
        let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        bytes.extend_from_slice(b"CustomActionJScriptActiveXObject");
        let findings = scan(Path::new("setup.msi"), &bytes);
        assert!(findings
            .iter()
            .any(|f| f.rule == "windows.msi-custom-action"));
    }
}
