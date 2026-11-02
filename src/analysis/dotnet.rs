//! .NET assembly analysis. Finds the CLI metadata root, extracts the `#Strings`
//! heap, and matches suspicious type/method names. This is a triage pass, not
//! an IL decompiler.

use crate::types::{Finding, Location, Severity};
use std::path::Path;

struct Pattern {
    /// Name that must be present in the string heap.
    anchor: &'static str,
    /// Any of these must also be present (empty means no companion needed).
    companions: &'static [&'static str],
    rule: &'static str,
    severity: Severity,
    message: &'static str,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        anchor: "Assembly",
        companions: &["LoadFrom", "LoadFile", "FromBase64String"],
        rule: "dotnet.assembly-load",
        severity: Severity::High,
        message: "loads an assembly at runtime",
    },
    Pattern {
        anchor: "DllImportAttribute",
        companions: &[],
        rule: "dotnet.pinvoke",
        severity: Severity::Medium,
        message: "calls native code through P/Invoke",
    },
    Pattern {
        anchor: "Process",
        companions: &["Start"],
        rule: "dotnet.process-start",
        severity: Severity::High,
        message: "starts a child process",
    },
    Pattern {
        anchor: "WebClient",
        companions: &["DownloadString", "DownloadData", "DownloadFile"],
        rule: "dotnet.download",
        severity: Severity::Medium,
        message: "downloads remote content",
    },
    Pattern {
        anchor: "MethodInfo",
        companions: &["Invoke"],
        rule: "dotnet.reflection",
        severity: Severity::Low,
        message: "invokes methods via reflection",
    },
    Pattern {
        anchor: "RegistryKey",
        companions: &["SetValue", "OpenSubKey"],
        rule: "dotnet.registry",
        severity: Severity::Medium,
        message: "reads or writes the registry",
    },
    Pattern {
        anchor: "ConfusedByAttribute",
        companions: &[],
        rule: "dotnet.obfuscator",
        severity: Severity::Medium,
        message: "contains a ConfuserEx obfuscation marker",
    },
    Pattern {
        anchor: "SmartAssembly",
        companions: &[],
        rule: "dotnet.obfuscator",
        severity: Severity::Medium,
        message: "contains a SmartAssembly obfuscation marker",
    },
    Pattern {
        anchor: "ObfuscatedBy",
        companions: &[],
        rule: "dotnet.obfuscator",
        severity: Severity::Medium,
        message: "contains an obfuscator marker",
    },
];

pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let strings = match metadata_strings(bytes) {
        Some(strings) if !strings.is_empty() => strings,
        _ => return Vec::new(),
    };
    let present = |name: &str| strings.iter().any(|s| s == name);

    let mut findings = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for pattern in PATTERNS {
        if !present(pattern.anchor) {
            continue;
        }
        let companion_ok = pattern.companions.is_empty()
            || pattern
                .companions
                .iter()
                .any(|companion| present(companion));
        if !companion_ok || !seen.insert(pattern.rule) {
            continue;
        }
        findings.push(Finding {
            id: format!("{}-{}", pattern.rule, path.display()),
            severity: pattern.severity,
            confidence: 0.55,
            rule: pattern.rule.to_string(),
            category: "dotnet".to_string(),
            location: Location {
                path: path.to_string_lossy().to_string(),
                line: None,
                column: None,
            },
            message: format!("Managed assembly {}", pattern.message),
            snippet: Some(pattern.anchor.to_string()),
            tags: vec!["dotnet".to_string()],
        });
    }
    findings
}

/// Extract the `#Strings` heap from the CLI metadata root.
pub fn metadata_strings(bytes: &[u8]) -> Option<Vec<String>> {
    let root = find_metadata_root(bytes)?;
    let streams = parse_root(bytes, root)?;
    for (name, offset, size) in streams {
        if name != "#Strings" {
            continue;
        }
        let start = root.checked_add(offset)?;
        let end = start.checked_add(size)?.min(bytes.len());
        if start >= end {
            return None;
        }
        return Some(
            bytes[start..end]
                .split(|byte| *byte == 0)
                .filter(|item| !item.is_empty() && item.len() < 512)
                .map(|item| String::from_utf8_lossy(item).to_string())
                .collect(),
        );
    }
    None
}

fn find_metadata_root(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 16 {
        return None;
    }
    // Search the PE headers/sections for the BSJB signature.
    bytes.windows(4).position(|window| window == b"BSJB")
}

type Streams = Vec<(String, usize, usize)>;

fn parse_root(bytes: &[u8], root: usize) -> Option<Streams> {
    let mut cursor = root + 12; // signature + major + minor + reserved
    let version_length = read_u32(bytes, cursor)? as usize;
    cursor += 4;
    let version_end = cursor.checked_add(version_length)?;
    if version_end > bytes.len() {
        return None;
    }
    // Version string is padded to a 4-byte boundary.
    cursor = version_end + (4 - version_length % 4) % 4;
    cursor += 2; // flags
    let stream_count = read_u16(bytes, cursor)? as usize;
    cursor += 2;

    let mut streams = Vec::new();
    for _ in 0..stream_count.min(64) {
        let offset = read_u32(bytes, cursor)? as usize;
        let size = read_u32(bytes, cursor + 4)? as usize;
        cursor += 8;

        let name_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != 0 {
            cursor += 1;
        }
        let name = String::from_utf8_lossy(&bytes[name_start..cursor]).to_string();
        let name_length = cursor - name_start + 1;
        cursor += (4 - name_length % 4) % 4;

        if cursor > bytes.len() {
            return None;
        }
        streams.push((name, offset, size));
    }
    Some(streams)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Build a minimal metadata root with one `#Strings` stream.
    fn assembly_with(strings: &[&str]) -> Vec<u8> {
        let mut heap = Vec::new();
        for text in strings {
            heap.extend_from_slice(text.as_bytes());
            heap.push(0);
        }

        let mut root = Vec::new();
        root.extend_from_slice(b"BSJB");
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&0u32.to_le_bytes());
        root.extend_from_slice(&4u32.to_le_bytes());
        root.extend_from_slice(b"v4.0");
        root.extend_from_slice(&0u16.to_le_bytes()); // flags
        root.extend_from_slice(&1u16.to_le_bytes()); // one stream

        // Stream header: offset, size, name "#Strings\0" padded to 4.
        let header_size = 8 + 12;
        let strings_offset = root.len() + header_size;
        root.extend_from_slice(&(strings_offset as u32).to_le_bytes());
        root.extend_from_slice(&(heap.len() as u32).to_le_bytes());
        root.extend_from_slice(b"#Strings\0\0\0\0");
        root.extend_from_slice(&heap);
        root
    }

    #[test]
    fn extracts_string_heap() {
        let assembly = assembly_with(&["Assembly", "LoadFrom", "Main"]);
        let strings = metadata_strings(&assembly).unwrap();
        assert!(strings.contains(&"LoadFrom".to_string()));
    }

    #[test]
    fn flags_assembly_load_and_process_start() {
        let assembly = assembly_with(&["Assembly", "LoadFrom", "Process", "Start"]);
        let findings = scan(&PathBuf::from("a.dll"), &assembly);
        assert!(findings.iter().any(|f| f.rule == "dotnet.assembly-load"));
        assert!(findings.iter().any(|f| f.rule == "dotnet.process-start"));
    }

    #[test]
    fn flags_obfuscator_markers() {
        let assembly = assembly_with(&["ConfusedByAttribute"]);
        let findings = scan(&PathBuf::from("a.dll"), &assembly);
        assert!(findings.iter().any(|f| f.rule == "dotnet.obfuscator"));
    }

    #[test]
    fn benign_assembly_is_quiet() {
        let assembly = assembly_with(&["System", "Console", "Main"]);
        assert!(scan(&PathBuf::from("a.dll"), &assembly).is_empty());
    }
}
