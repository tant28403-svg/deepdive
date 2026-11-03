//! Android APK analysis: scan every `classes*.dex` string table for dangerous
//! API references. A full DEX disassembler is out of scope for this pass.

use crate::types::{Finding, Location, Severity};
use std::path::Path;

struct Pattern {
    /// String that must be present (class descriptor or method name).
    class: &'static str,
    /// Optional second string that must also be present.
    companion: Option<&'static str>,
    rule: &'static str,
    severity: Severity,
    message: &'static str,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        class: "Ljava/lang/Runtime;",
        companion: Some("exec"),
        rule: "android.runtime-exec",
        severity: Severity::High,
        message: "runtime process execution",
    },
    Pattern {
        class: "Ljava/lang/ProcessBuilder;",
        companion: Some("start"),
        rule: "android.process-builder",
        severity: Severity::High,
        message: "process execution via ProcessBuilder",
    },
    Pattern {
        class: "Ldalvik/system/DexClassLoader;",
        companion: None,
        rule: "android.dynamic-code-loading",
        severity: Severity::Medium,
        message: "loads code from an external DEX",
    },
    Pattern {
        class: "Ldalvik/system/PathClassLoader;",
        companion: None,
        rule: "android.dynamic-code-loading",
        severity: Severity::Low,
        message: "loads code via PathClassLoader",
    },
    Pattern {
        class: "Landroid/telephony/SmsManager;",
        companion: None,
        rule: "android.sms",
        severity: Severity::High,
        message: "can send premium SMS",
    },
    Pattern {
        class: "Ljava/lang/reflect/Method;",
        companion: Some("invoke"),
        rule: "android.reflection",
        severity: Severity::Low,
        message: "uses reflection to invoke methods",
    },
    Pattern {
        class: "Landroid/content/pm/PackageInstaller;",
        companion: None,
        rule: "android.package-install",
        severity: Severity::Medium,
        message: "installs or updates packages",
    },
    Pattern {
        class: "Lsun/misc/Unsafe;",
        companion: None,
        rule: "android.unsafe-memory",
        severity: Severity::Medium,
        message: "uses sun.misc.Unsafe",
    },
];

pub fn scan_apk(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return findings;
    };
    for index in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(index) else {
            continue;
        };
        let Ok(name) = entry.name() else {
            continue;
        };
        let name = name.to_string();
        if !(name.ends_with(".dex") || name == "classes.dex") {
            continue;
        }
        let mut buffer = Vec::new();
        if std::io::Read::read_to_end(&mut entry, &mut buffer).is_ok() {
            findings.extend(scan_dex(path, &buffer));
        }
    }
    findings
}

pub fn scan_dex(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let strings = dex_strings(bytes);
    if strings.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for pattern in PATTERNS {
        let has_class = strings.iter().any(|s| s == pattern.class);
        let has_companion = pattern
            .companion
            .map(|companion| strings.iter().any(|s| s == companion))
            .unwrap_or(true);
        if has_class && has_companion && seen.insert(pattern.rule) {
            findings.push(Finding {
                id: format!("{}-{}", pattern.rule, path.display()),
                severity: pattern.severity,
                confidence: 0.6,
                rule: pattern.rule.to_string(),
                category: "android".to_string(),
                location: Location {
                    path: path.to_string_lossy().to_string(),
                    line: None,
                    column: None,
                },
                message: format!("DEX bytecode uses {} ({})", pattern.message, pattern.class),
                snippet: Some(pattern.class.to_string()),
                tags: vec!["android".to_string()],
            });
        }
    }
    findings
}

/// Extract the DEX string table.
pub fn dex_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if bytes.len() < 112 || &bytes[0..4] != b"dex\n" {
        return out;
    }
    let count = read_u32(bytes, 56) as usize;
    let offset = read_u32(bytes, 60) as usize;
    // Guard against absurd tables and truncated files.
    if count > 500_000 || offset == 0 {
        return out;
    }
    for index in 0..count {
        let id_offset = offset + index * 4;
        if id_offset + 4 > bytes.len() {
            break;
        }
        let data_offset = read_u32(bytes, id_offset) as usize;
        if data_offset >= bytes.len() {
            continue;
        }
        let (length, mut cursor) = read_uleb128(bytes, data_offset);
        if length == 0 || length > 4096 {
            continue;
        }
        let end = (cursor + length).min(bytes.len());
        if cursor < end {
            out.push(String::from_utf8_lossy(&bytes[cursor..end]).to_string());
        }
        cursor = end;
        let _ = cursor;
    }
    out
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    if offset + 4 > bytes.len() {
        return 0;
    }
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_uleb128(bytes: &[u8], mut offset: usize) -> (usize, usize) {
    let mut value = 0usize;
    let mut shift = 0;
    while offset < bytes.len() && shift < 32 {
        let byte = bytes[offset];
        offset += 1;
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (value, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn uleb(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    /// Build a minimal DEX with just a string table.
    fn dex_with(strings: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0u8; 112];
        bytes[0..4].copy_from_slice(b"dex\n");
        bytes[4..8].copy_from_slice(b"035\0");

        let table_offset = 112usize;
        let data_offset = table_offset + strings.len() * 4;
        let mut data = Vec::new();
        let mut ids = Vec::new();
        for text in strings {
            ids.push(data_offset + data.len());
            data.extend_from_slice(&uleb(text.len()));
            data.extend_from_slice(text.as_bytes());
            data.push(0);
        }

        bytes[56..60].copy_from_slice(&(strings.len() as u32).to_le_bytes());
        bytes[60..64].copy_from_slice(&(table_offset as u32).to_le_bytes());

        let mut ids_bytes = Vec::new();
        for id in ids {
            ids_bytes.extend_from_slice(&(id as u32).to_le_bytes());
        }
        bytes.extend_from_slice(&ids_bytes);
        bytes.extend_from_slice(&data);
        bytes
    }

    #[test]
    fn extracts_dex_strings() {
        let dex = dex_with(&["Ljava/lang/Runtime;", "exec", "hello"]);
        let strings = dex_strings(&dex);
        assert!(strings.contains(&"Ljava/lang/Runtime;".to_string()));
        assert!(strings.contains(&"hello".to_string()));
    }

    #[test]
    fn flags_runtime_exec() {
        let dex = dex_with(&["Ljava/lang/Runtime;", "exec"]);
        let findings = scan_dex(&PathBuf::from("classes.dex"), &dex);
        assert!(findings.iter().any(|f| f.rule == "android.runtime-exec"));
    }

    #[test]
    fn flags_dynamic_loading() {
        let dex = dex_with(&["Ldalvik/system/DexClassLoader;"]);
        let findings = scan_dex(&PathBuf::from("classes.dex"), &dex);
        assert!(findings
            .iter()
            .any(|f| f.rule == "android.dynamic-code-loading"));
    }

    #[test]
    fn benign_dex_is_quiet() {
        let dex = dex_with(&["Landroid/app/Activity;", "onCreate"]);
        assert!(scan_dex(&PathBuf::from("classes.dex"), &dex).is_empty());
    }
}
