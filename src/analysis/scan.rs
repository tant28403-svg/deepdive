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
    let content = std::fs::read_to_string(path).unwrap_or_default();
    scan_file(path, &content)
}
