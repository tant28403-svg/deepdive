use crate::analysis::file_type::FileType;
use crate::types::Finding;
use std::path::Path;

pub fn scan_file(path: &Path, _content: &str) -> Vec<Finding> {
    let ft = crate::analysis::file_type::detect(path);
    let mut findings = Vec::new();
    match ft {
        FileType::Source | FileType::Script | FileType::Text | FileType::Config => {
            findings.extend(crate::analysis::source::scan(path, _content));
            findings.extend(crate::analysis::secrets::scan(path, _content));
            findings.extend(crate::analysis::obfuscation::scan(path, _content));
        }
        FileType::BinaryPe | FileType::BinaryElf | FileType::BinaryMachO => {
            if let Ok(bytes) = std::fs::read(path) {
                findings.extend(crate::analysis::binary::scan(path, &bytes));
            }
        }
        _ => {}
    }
    findings
}

pub fn read_and_scan(path: &Path) -> Vec<Finding> {
    match std::fs::read_to_string(path) {
        Ok(content) => scan_file(path, &content),
        Err(_) => Vec::new(),
    }
}
