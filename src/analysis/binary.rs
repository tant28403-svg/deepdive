use crate::types::{Finding, Location, Severity};
use goblin::pe::PE;
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
                        tags: vec![],
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
