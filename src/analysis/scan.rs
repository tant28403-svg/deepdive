use crate::analysis::file_type::FileType;
use crate::types::Finding;
use std::path::Path;

pub fn scan_file(path: &Path, content: &str) -> Vec<Finding> {
    let ft = crate::analysis::file_type::detect(path);
    let mut findings = Vec::new();
    match ft {
        FileType::Source | FileType::Script | FileType::Text | FileType::Config => {
            findings.extend(crate::analysis::source::scan(path, content));
            findings.extend(crate::analysis::secrets::scan(path, content));
            findings.extend(crate::analysis::obfuscation::scan(path, content));
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
