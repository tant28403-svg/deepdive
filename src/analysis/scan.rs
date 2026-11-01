use crate::analysis::file_type::FileType;
use crate::types::Finding;
use std::path::Path;

pub fn scan_file(path: &Path, content: &str) -> Vec<Finding> {
    let ft = crate::analysis::file_type::detect(path);
    let mut findings = Vec::new();
    let is_notebook = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("ipynb"))
        .unwrap_or(false);
    match ft {
        FileType::Source | FileType::Script | FileType::Text | FileType::Config => {
            if !is_notebook {
                findings.extend(crate::analysis::source::scan(path, content));
                findings.extend(crate::analysis::secrets::scan(path, content));
                findings.extend(crate::analysis::obfuscation::scan(path, content));
                findings.extend(crate::analysis::ast::scan_ast(path, content));
                // Automatic deobfuscation: decode and rescan payloads.
                for decoded in crate::analysis::deobfuscate::deobfuscate_deep(content, 3) {
                    let mut sub = crate::analysis::source::scan(path, &decoded);
                    for f in &mut sub {
                        f.message = format!("[deobfuscated] {}", f.message);
                        f.tags.push("deobfuscated".to_string());
                    }
                    findings.extend(sub);
                    let mut sub = crate::analysis::secrets::scan(path, &decoded);
                    for f in &mut sub {
                        f.message = format!("[deobfuscated] {}", f.message);
                        f.tags.push("deobfuscated".to_string());
                    }
                    findings.extend(sub);
                    let mut sub = crate::analysis::obfuscation::scan(path, &decoded);
                    for f in &mut sub {
                        f.message = format!("[deobfuscated] {}", f.message);
                        f.tags.push("deobfuscated".to_string());
                    }
                    findings.extend(sub);
                }
            }
        }
        FileType::BinaryPe | FileType::BinaryElf | FileType::BinaryMachO => {
            if let Ok(bytes) = std::fs::read(path) {
                findings.extend(crate::analysis::binary::scan(path, &bytes));
            }
        }
        FileType::Archive => {
            if let Ok(bytes) = std::fs::read(path) {
                findings.extend(crate::analysis::archive::scan(path, &bytes));
            }
        }
        FileType::Bytecode => {
            // JVM/Android archives are zip containers; .class/.wasm analysis is a v2 item.
            if let Ok(bytes) = std::fs::read(path) {
                if bytes.len() >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4B {
                    findings.extend(crate::analysis::archive::scan(path, &bytes));
                }
            }
        }
        FileType::Package => {
            if let Ok(bytes) = std::fs::read(path) {
                findings.extend(crate::analysis::archive::scan(path, &bytes));
            }
        }
        _ => {}
    }
    // Build-script / CI / Dockerfile analysis (by filename).
    findings.extend(crate::analysis::build::scan(path, content));
    // Document analysis (PDF, Office, HTML, SVG, Jupyter).
    if let Ok(bytes) = std::fs::read(path) {
        findings.extend(crate::analysis::document::scan(path, &bytes));
    }
    // Polyglot carving: scan embedded payloads.
    if let Ok(bytes) = std::fs::read(path) {
        findings.extend(crate::analysis::polyglot::scan_carved(path, &bytes));
    }
    findings
}

pub fn scan_bytes(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(crate::analysis::binary::scan(path, bytes));
    findings.extend(crate::analysis::document::scan(path, bytes));
    if let Ok(text) = std::str::from_utf8(bytes) {
        findings.extend(crate::analysis::source::scan(path, text));
        findings.extend(crate::analysis::secrets::scan(path, text));
        findings.extend(crate::analysis::obfuscation::scan(path, text));
    }
    findings
}

pub fn read_and_scan(path: &Path) -> Vec<Finding> {
    let ft = crate::analysis::file_type::detect(path);
    let content = match ft {
        FileType::Source
        | FileType::Script
        | FileType::Text
        | FileType::Config
        | FileType::Unknown => read_text(path),
        _ => String::new(),
    };
    scan_file(path, &content)
}

/// Decode a text file, handling UTF-16 BOMs in addition to UTF-8.
pub fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], false);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).to_string(),
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn read_text(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => decode_text(&bytes),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf16_le_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "eval(atob('x'))".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_text(&bytes), "eval(atob('x'))");
    }

    #[test]
    fn passes_through_utf8() {
        assert_eq!(decode_text(b"hello"), "hello");
    }
}
