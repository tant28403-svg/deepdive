use crate::analysis::windows_extras::all_strings;
use crate::types::{Finding, Location, Severity};
use goblin::pe::PE;
use md5::Md5;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let path_str = path.display().to_string();

    // PE
    if let Ok(pe) = PE::parse(bytes) {
        // Sections: flag W+X and high entropy.
        for section in &pe.sections {
            let name = section.name().unwrap_or("?").to_string();
            let chars = section.characteristics;
            let writable = chars & 0x80000000 != 0;
            let executable = chars & 0x20000000 != 0;
            if writable && executable {
                out.push(Finding {
                    id: format!("binary.pe-wx-section-{}-{}", path_str, name),
                    severity: Severity::High,
                    confidence: 0.85,
                    rule: "binary.pe-wx-section".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!("Section '{}' is both writable and executable (W+X)", name),
                    snippet: None,
                    tags: vec![],
                });
            }
            // Entropy of section data.
            let raw = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            if raw + size <= bytes.len() && size > 0 {
                let data = &bytes[raw..raw + size];
                let e = entropy(data);
                if e > 7.2 {
                    out.push(Finding {
                        id: format!("binary.pe-high-entropy-{}-{}", path_str, name),
                        severity: Severity::Medium,
                        confidence: 0.6,
                        rule: "binary.pe-high-entropy".to_string(),
                        category: "binary".to_string(),
                        location: Location {
                            path: path_str.clone(),
                            line: None,
                            column: None,
                        },
                        message: format!(
                            "Section '{}' has high entropy ({:.2}) — possibly packed/encrypted",
                            name, e
                        ),
                        snippet: None,
                        tags: vec![format!("section-sha256:{}", short_hash(data))],
                    });
                }
            }
            // Packer section names.
            let lname = name.to_lowercase();
            for packer in [".upx", ".aspack", ".themida", ".vmp", ".petite", ".mpress"] {
                if lname.starts_with(packer) {
                    out.push(Finding {
                        id: format!("binary.pe-packer-{}-{}", path_str, name),
                        severity: Severity::High,
                        confidence: 0.9,
                        rule: "binary.pe-packer".to_string(),
                        category: "binary".to_string(),
                        location: Location {
                            path: path_str.clone(),
                            line: None,
                            column: None,
                        },
                        message: format!("Known packer section '{}' detected", name),
                        snippet: None,
                        tags: vec![],
                    });
                }
            }
        }

        // Imports: flag dangerous ones.
        let dangerous_imports = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "NtMapViewOfSection",
            "QueueUserAPC",
            "SetWindowsHookEx",
            "GetAsyncKeyState",
            "CredEnumerate",
            "MiniDumpWriteDump",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "URLDownloadToFile",
            "InternetReadFile",
            "WinHttpOpen",
            "RegSetValueEx",
            "CreateService",
            "CryptEncrypt",
        ];
        let mut found_dangerous: Vec<String> = Vec::new();
        for imp in &pe.imports {
            let name = imp.name.clone();
            if dangerous_imports.iter().any(|d| *d == name) {
                found_dangerous.push(name.to_string());
            }
        }
        // dedupe
        found_dangerous.sort();
        found_dangerous.dedup();
        if !found_dangerous.is_empty() {
            out.push(Finding {
                id: format!("binary.pe-dangerous-imports-{}", path_str),
                severity: Severity::High,
                confidence: 0.8,
                rule: "binary.pe-dangerous-imports".to_string(),
                category: "binary".to_string(),
                location: Location {
                    path: path_str.clone(),
                    line: None,
                    column: None,
                },
                message: format!("Dangerous imports: {}", found_dangerous.join(", ")),
                snippet: None,
                tags: vec![],
            });
        }

        let imphash = import_hash(&pe);

        // Overlay data: bytes after last section.
        let mut end = 0usize;
        for section in &pe.sections {
            let s = section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
            if s > end {
                end = s;
            }
        }
        if end > 0 && end < bytes.len() {
            let overlay = &bytes[end..];
            if overlay.len() > 64 {
                out.push(Finding {
                    id: format!("binary.pe-overlay-{}", path_str),
                    severity: Severity::Medium,
                    confidence: 0.7,
                    rule: "binary.pe-overlay".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!(
                        "Overlay data of {} bytes after last section (possible appended payload)",
                        overlay.len()
                    ),
                    snippet: None,
                    tags: vec![],
                });
            }
        }

        // Unsigned: check if any certificate directory entry.
        let has_cert = pe
            .header
            .optional_header
            .map(|oh| {
                oh.data_directories
                    .get_certificate_table()
                    .map(|d| d.virtual_address != 0)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !has_cert {
            out.push(Finding {
                id: format!("binary.pe-unsigned-{}", path_str),
                severity: Severity::Low,
                confidence: 0.5,
                rule: "binary.pe-unsigned".to_string(),
                category: "binary".to_string(),
                location: Location {
                    path: path_str.clone(),
                    line: None,
                    column: None,
                },
                message: "PE has no Authenticode signature".to_string(),
                snippet: None,
                tags: vec![],
            });
        }

        // Embedded PE payloads (appended/overlay or stashed in a section).
        let embedded = find_embedded_pe_offsets(bytes);
        if !embedded.is_empty() {
            out.push(Finding {
                id: format!("binary.pe-embedded-{}", path_str),
                severity: Severity::High,
                confidence: 0.8,
                rule: "binary.pe-embedded".to_string(),
                category: "binary".to_string(),
                location: Location {
                    path: path_str.clone(),
                    line: None,
                    column: None,
                },
                message: format!(
                    "{} embedded PE payload(s) found at offsets {}",
                    embedded.len(),
                    embedded
                        .iter()
                        .take(8)
                        .map(|o| format!("0x{:x}", o))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                snippet: None,
                tags: vec!["embedded-pe".to_string()],
            });
        }

        // Version metadata: look for masquerading indicators.
        let original = utf16_value_after(bytes, "OriginalFilename");
        let company = utf16_value_after(bytes, "CompanyName");
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let system_binaries = [
            "svchost.exe",
            "lsass.exe",
            "csrss.exe",
            "services.exe",
            "winlogon.exe",
            "explorer.exe",
            "smss.exe",
            "spoolsv.exe",
            "lsm.exe",
        ];
        if let Some(orig) = &original {
            let orig_lower = orig.to_lowercase();
            let claims_system = system_binaries.iter().any(|s| orig_lower.contains(s));
            let claims_microsoft = company
                .as_deref()
                .map(|c| c.to_lowercase().contains("microsoft"))
                .unwrap_or(false);
            if claims_system && !claims_microsoft {
                out.push(Finding {
                    id: format!("binary.pe-masquerade-system-{}", path_str),
                    severity: Severity::High,
                    confidence: 0.75,
                    rule: "binary.pe-masquerade-system".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!(
                        "PE claims to be system binary '{}' but is not signed as Microsoft",
                        orig
                    ),
                    snippet: Some(format!(
                        "OriginalFilename={}; CompanyName={}",
                        orig,
                        company.as_deref().unwrap_or("<missing>")
                    )),
                    tags: vec!["masquerade".to_string()],
                });
            }
            if !file_name.is_empty() && !orig.eq_ignore_ascii_case(&file_name) {
                out.push(Finding {
                    id: format!("binary.pe-version-mismatch-{}", path_str),
                    severity: Severity::Low,
                    confidence: 0.5,
                    rule: "binary.pe-version-mismatch".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!(
                        "Version metadata OriginalFilename '{}' differs from file name '{}'",
                        orig, file_name
                    ),
                    snippet: None,
                    tags: vec!["masquerade".to_string()],
                });
            }
        }
        if let Some(c) = &company {
            if c.to_lowercase().contains("microsoft") && is_temp_or_download_path(path) {
                out.push(Finding {
                    id: format!("binary.pe-microsoft-in-temp-{}", path_str),
                    severity: Severity::High,
                    confidence: 0.7,
                    rule: "binary.pe-microsoft-in-temp".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!(
                        "PE claims CompanyName '{}' but lives in a temp/download path",
                        c
                    ),
                    snippet: None,
                    tags: vec!["masquerade".to_string()],
                });
            }
        }

        // Attach the import hash to every PE finding for clustering.
        for f in out.iter_mut().filter(|f| f.rule.starts_with("binary.pe")) {
            f.tags.push(format!("imphash:{}", imphash));
        }
    }

    // ELF: basic checks via goblin.
    if let Ok(elf) = goblin::elf::Elf::parse(bytes) {
        // Flag RWX segments.
        for ph in &elf.program_headers {
            // PF_X=1, PF_W=2
            let w = ph.p_flags & 0x2 != 0;
            let x = ph.p_flags & 0x1 != 0;
            if w && x {
                out.push(Finding {
                    id: format!("binary.elf-rwx-{}", path_str),
                    severity: Severity::High,
                    confidence: 0.85,
                    rule: "binary.elf-rwx-segment".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: "ELF segment is both writable and executable (W+X)".to_string(),
                    snippet: None,
                    tags: vec![],
                });
                break;
            }
        }
        // Dangerous symbols/imports.
        let dangerous = ["system", "execve", "popen", "dlopen", "ptrace"];
        for sym in elf.dynsyms.iter() {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
            if dangerous.contains(&name) {
                out.push(Finding {
                    id: format!("binary.elf-dangerous-sym-{}-{}", path_str, name),
                    severity: Severity::Medium,
                    confidence: 0.6,
                    rule: "binary.elf-dangerous-symbol".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!("ELF imports dangerous symbol: {}", name),
                    snippet: None,
                    tags: vec![],
                });
            }
        }

        // High-entropy sections (packed/encrypted data).
        for sh in &elf.section_headers {
            let off = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            if size > 4096 && off + size <= bytes.len() {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?");
                let e = entropy(&bytes[off..off + size]);
                if e > 7.2 {
                    out.push(Finding {
                        id: format!("binary.elf-high-entropy-{}-{}", path_str, name),
                        severity: Severity::Medium,
                        confidence: 0.6,
                        rule: "binary.elf-high-entropy".to_string(),
                        category: "binary".to_string(),
                        location: Location {
                            path: path_str.clone(),
                            line: None,
                            column: None,
                        },
                        message: format!(
                            "ELF section '{}' has high entropy ({:.2}) — possibly packed/encrypted",
                            name, e
                        ),
                        snippet: None,
                        tags: vec![format!(
                            "section-sha256:{}",
                            short_hash(&bytes[off..off + size])
                        )],
                    });
                }
            }
        }

        // Suspicious interpreter / library search paths.
        if let Some(interp) = elf.interpreter {
            let lower = interp.to_lowercase();
            if lower.contains("/tmp/") || lower.contains("/var/tmp/") {
                out.push(Finding {
                    id: format!("binary.elf-temp-interpreter-{}", path_str),
                    severity: Severity::High,
                    confidence: 0.8,
                    rule: "binary.elf-temp-interpreter".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!(
                        "ELF interpreter resolves to a writable temp path: {}",
                        interp
                    ),
                    snippet: Some(interp.to_string()),
                    tags: vec!["rpath".to_string()],
                });
            }
        }
        for rp in elf.rpaths.iter().chain(elf.runpaths.iter()) {
            let lower = rp.to_lowercase();
            let relative = rp.starts_with('.')
                || lower.contains("$origin/..")
                || lower.contains("/tmp/")
                || lower.contains("/var/tmp/");
            if relative {
                out.push(Finding {
                    id: format!("binary.elf-relative-rpath-{}-{}", path_str, rp),
                    severity: Severity::Medium,
                    confidence: 0.7,
                    rule: "binary.elf-relative-rpath".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!(
                        "ELF library search path is relative or writable: {} (library hijack risk)",
                        rp
                    ),
                    snippet: Some(rp.to_string()),
                    tags: vec!["rpath".to_string()],
                });
            }
        }
    }

    // Mach-O: segments, protections, dylibs, rpaths.
    if let Ok(mach) = goblin::mach::MachO::parse(bytes, 0) {
        for seg in &mach.segments {
            let w = seg.initprot & 0x2 != 0;
            let x = seg.initprot & 0x4 != 0;
            if w && x {
                let name = seg.name().unwrap_or("?");
                out.push(Finding {
                    id: format!("binary.macho-wx-{}-{}", path_str, name),
                    severity: Severity::High,
                    confidence: 0.85,
                    rule: "binary.macho-wx-segment".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!("Mach-O segment '{}' is writable and executable (W+X)", name),
                    snippet: None,
                    tags: vec![],
                });
            }
        }
        for lib in &mach.libs {
            let lower = lib.to_lowercase();
            if lower.contains("/tmp/") || lower.contains("/users/shared/") {
                out.push(Finding {
                    id: format!("binary.macho-untrusted-dylib-{}-{}", path_str, lib),
                    severity: Severity::Medium,
                    confidence: 0.7,
                    rule: "binary.macho-untrusted-dylib".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!("Mach-O loads a dylib from a user-writable path: {}", lib),
                    snippet: Some(lib.to_string()),
                    tags: vec!["dylib".to_string()],
                });
            }
        }
        for rp in &mach.rpaths {
            if rp.starts_with('.') || rp.contains("..") {
                out.push(Finding {
                    id: format!("binary.macho-relative-rpath-{}-{}", path_str, rp),
                    severity: Severity::Medium,
                    confidence: 0.7,
                    rule: "binary.macho-relative-rpath".to_string(),
                    category: "binary".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: format!("Mach-O rpath is relative: {} (dylib hijack risk)", rp),
                    snippet: Some(rp.to_string()),
                    tags: vec!["rpath".to_string()],
                });
            }
        }
    }

    // String intelligence: URLs, IPs, PowerShell, registry, base64 blobs.
    out.extend(string_findings(path, bytes));

    out
}

fn short_hash(data: &[u8]) -> String {
    hex::encode(&Sha256::digest(data)[..8])
}

fn import_hash(pe: &PE) -> String {
    let mut pairs: Vec<String> = pe
        .imports
        .iter()
        .map(|i| format!("{}.{}", i.dll.to_lowercase(), i.name.to_lowercase()))
        .collect();
    pairs.sort();
    pairs.dedup();
    hex::encode(Md5::digest(pairs.join(",").as_bytes()))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_embedded_pe_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut start = 1usize;
    while offsets.len() < 16 && start < bytes.len() {
        let Some(pos) = find_subslice(&bytes[start..], b"MZ") else {
            break;
        };
        let abs = start + pos;
        if abs + 0x40 < bytes.len() && PE::parse(&bytes[abs..]).is_ok() {
            offsets.push(abs);
        }
        start = abs + 2;
    }
    offsets
}

fn utf16_value_after(bytes: &[u8], key: &str) -> Option<String> {
    let mut needle = Vec::new();
    for unit in key.encode_utf16() {
        needle.extend_from_slice(&unit.to_le_bytes());
    }
    let pos = find_subslice(bytes, &needle)?;
    let rest = &bytes[pos + needle.len()..];
    let mut value = String::new();
    let mut i = 0usize;
    while i + 1 < rest.len() {
        let unit = u16::from_le_bytes([rest[i], rest[i + 1]]);
        if unit == 0 {
            if value.is_empty() {
                i += 2;
                continue;
            }
            break;
        }
        let Some(c) = char::from_u32(unit as u32) else {
            if value.is_empty() {
                i += 2;
                continue;
            }
            break;
        };
        if c.is_control() {
            if value.is_empty() {
                i += 2;
                continue;
            }
            break;
        }
        value.push(c);
        i += 2;
    }
    if value.is_empty() {
        None
    } else {
        Some(value.chars().take(120).collect())
    }
}

fn is_temp_or_download_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    [
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\",
        "\\downloads\\",
        "/tmp/",
        "/var/tmp/",
        "/downloads/",
    ]
    .iter()
    .any(|p| lower.contains(p))
}

fn looks_like_ipv4(s: &str) -> bool {
    for token in s.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
        {
            return true;
        }
    }
    false
}

fn is_base64_blob(s: &str) -> bool {
    s.len() >= 32
        && s.len().is_multiple_of(4)
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && (s.ends_with('=') || s.chars().any(|c| c.is_ascii_uppercase()))
        && s.chars().any(|c| c.is_ascii_lowercase())
}

fn string_findings(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    use std::collections::BTreeSet;

    let cap = bytes.len().min(32 * 1024 * 1024);
    let strings = all_strings(&bytes[..cap]);
    let mut urls = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut powershell = BTreeSet::new();
    let mut registry = BTreeSet::new();
    let mut base64 = 0usize;

    for s in &strings {
        if s.len() > 400 {
            continue;
        }
        let lower = s.to_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            urls.insert(s.clone());
        } else if looks_like_ipv4(s) {
            ips.insert(s.clone());
        }
        if lower.contains("powershell")
            && (lower.contains("-enc")
                || lower.contains("-encodedcommand")
                || lower.contains("downloadstring")
                || lower.contains("frombase64string")
                || lower.contains("-windowstyle hidden")
                || lower.contains("-w hidden"))
        {
            powershell.insert(s.clone());
        }
        if lower.contains("\\currentversion\\run")
            || lower.contains("image file execution options")
            || lower.contains("appinit_dlls")
        {
            registry.insert(s.clone());
        }
        if is_base64_blob(s) {
            base64 += 1;
        }
    }

    let path_str = path.display().to_string();
    let mut out = Vec::new();
    let mut push = |rule: &str, severity: Severity, message: String, items: Vec<String>| {
        out.push(Finding {
            id: format!("{}-{}", rule, path_str),
            severity,
            confidence: 0.65,
            rule: rule.to_string(),
            category: "binary".to_string(),
            location: Location {
                path: path_str.clone(),
                line: None,
                column: None,
            },
            message,
            snippet: Some(
                items
                    .iter()
                    .take(8)
                    .map(|s| s.chars().take(160).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
            tags: vec!["strings".to_string()],
        });
    };

    if !powershell.is_empty() {
        push(
            "binary.strings-powershell",
            Severity::High,
            format!(
                "Binary contains {} PowerShell command string(s) with encoded/hidden/download indicators",
                powershell.len()
            ),
            powershell.into_iter().collect(),
        );
    }
    if !urls.is_empty() {
        push(
            "binary.strings-urls",
            Severity::Medium,
            format!("Binary contains {} embedded URL(s)", urls.len()),
            urls.into_iter().collect(),
        );
    }
    if !registry.is_empty() {
        push(
            "binary.strings-registry",
            Severity::Medium,
            format!(
                "Binary references {} registry persistence path(s)",
                registry.len()
            ),
            registry.into_iter().collect(),
        );
    }
    if !ips.is_empty() {
        push(
            "binary.strings-ips",
            Severity::Low,
            format!("Binary contains {} embedded IPv4 address(es)", ips.len()),
            ips.into_iter().collect(),
        );
    }
    if base64 >= 3 {
        push(
            "binary.strings-base64",
            Severity::Low,
            format!("Binary contains {} long base64-like blob(s)", base64),
            Vec::new(),
        );
    }
    out
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut e = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            e -= p * p.log2();
        }
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_utf16_version_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 8]);
        for unit in "OriginalFilename".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        for unit in "svchost.exe".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            utf16_value_after(&bytes, "OriginalFilename").as_deref(),
            Some("svchost.exe")
        );
    }

    #[test]
    fn recognizes_ipv4_and_base64() {
        assert!(looks_like_ipv4("192.168.1.10"));
        assert!(looks_like_ipv4("http://10.0.0.1:8080/x"));
        assert!(!looks_like_ipv4("version 1.2.3"));
        assert!(is_base64_blob("VGhpcyBpcyBhIHNlY3JldCBwYXlsb2FkIQ=="));
        assert!(!is_base64_blob("short"));
    }

    #[test]
    fn finds_embedded_pe_offsets() {
        let data = b"junkjunkjunkMZnotape";
        assert!(find_embedded_pe_offsets(data).is_empty());
    }
}
