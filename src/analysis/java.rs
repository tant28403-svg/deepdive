//! Java bytecode and JAR analysis. This reads the constant pool for a
//! conservative set of dangerous references; it is not a full disassembler.

use crate::types::{Finding, Location, Severity};
use std::path::Path;

struct Pattern {
    needle: &'static str,
    severity: Severity,
    confidence: f32,
    message: &'static str,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        needle: "java/lang/ProcessBuilder",
        severity: Severity::High,
        confidence: 0.6,
        message: "references java.lang.ProcessBuilder (process execution)",
    },
    Pattern {
        needle: "javax/naming/InitialContext",
        severity: Severity::Medium,
        confidence: 0.55,
        message: "references JNDI InitialContext (remote class loading)",
    },
    Pattern {
        needle: "java/io/ObjectInputStream",
        severity: Severity::Medium,
        confidence: 0.5,
        message: "references Java deserialization",
    },
    Pattern {
        needle: "defineClass",
        severity: Severity::High,
        confidence: 0.5,
        message: "defines a class at runtime",
    },
    Pattern {
        needle: "java/net/URLClassLoader",
        severity: Severity::Medium,
        confidence: 0.5,
        message: "loads classes from a URL",
    },
    Pattern {
        needle: "javax/script/ScriptEngine",
        severity: Severity::Medium,
        confidence: 0.5,
        message: "uses a scripting engine",
    },
    Pattern {
        needle: "/bin/sh",
        severity: Severity::High,
        confidence: 0.6,
        message: "contains a shell command literal",
    },
    Pattern {
        needle: "cmd.exe",
        severity: Severity::High,
        confidence: 0.6,
        message: "contains a Windows shell command literal",
    },
];

pub fn scan_class(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let constants = utf8_constants(bytes);
    match_patterns(path, &constants.join("\n"))
}

/// Scan every `.class` entry inside a JAR/WAR/APK zip container.
pub fn scan_archive(path: &Path, bytes: &[u8]) -> Vec<Finding> {
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
        if !name.ends_with(".class") {
            continue;
        }
        let mut buffer = Vec::new();
        if std::io::Read::read_to_end(&mut entry, &mut buffer).is_ok() {
            findings.extend(scan_class(path, &buffer));
        }
    }
    findings
}

fn match_patterns(path: &Path, joined: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for pattern in PATTERNS {
        if joined.contains(pattern.needle) {
            findings.push(Finding {
                id: format!("java.{}-{}", pattern.needle, path.display()),
                severity: pattern.severity,
                confidence: pattern.confidence,
                rule: "java.dangerous-reference".to_string(),
                category: "java".to_string(),
                location: Location {
                    path: path.to_string_lossy().to_string(),
                    line: None,
                    column: None,
                },
                message: pattern.message.to_string(),
                snippet: Some(pattern.needle.to_string()),
                tags: vec!["java".to_string()],
            });
        }
    }
    findings
}

/// Extract the UTF-8 constants from a class file constant pool.
pub fn utf8_constants(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if bytes.len() < 10 || bytes[0..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
        return out;
    }
    let mut cursor = 8usize;
    let count = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
    cursor += 2;

    let mut index = 1usize;
    while index < count && cursor < bytes.len() {
        let tag = bytes[cursor];
        cursor += 1;
        match tag {
            1 => {
                if cursor + 2 > bytes.len() {
                    break;
                }
                let len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                cursor += 2;
                if cursor + len > bytes.len() {
                    break;
                }
                out.push(String::from_utf8_lossy(&bytes[cursor..cursor + len]).to_string());
                cursor += len;
            }
            3 | 4 => cursor += 4,
            5 | 6 => {
                cursor += 8;
                index += 1;
            }
            7 | 8 | 16 | 19 | 20 => cursor += 2,
            9 | 10 | 11 | 12 | 17 | 18 => cursor += 4,
            15 => cursor += 3,
            _ => break,
        }
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn class_with(texts: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37];
        let count = texts.len() + 1;
        bytes.extend_from_slice(&(count as u16).to_be_bytes());
        for text in texts {
            bytes.push(1);
            bytes.extend_from_slice(&(text.len() as u16).to_be_bytes());
            bytes.extend_from_slice(text.as_bytes());
        }
        bytes
    }

    #[test]
    fn extracts_utf8_constants() {
        let class = class_with(&["java/lang/Object", "main"]);
        assert_eq!(utf8_constants(&class), vec!["java/lang/Object", "main"]);
    }

    #[test]
    fn flags_process_builder() {
        let class = class_with(&["java/lang/ProcessBuilder", "/bin/sh"]);
        let findings = scan_class(&PathBuf::from("A.class"), &class);
        assert!(findings
            .iter()
            .any(|f| f.rule == "java.dangerous-reference"));
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn benign_class_is_quiet() {
        let class = class_with(&["java/lang/Object", "toString"]);
        assert!(scan_class(&PathBuf::from("A.class"), &class).is_empty());
    }
}
