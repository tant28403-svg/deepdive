use crate::analysis::file_type::FileType;
use crate::analysis::scan;
use crate::types::Finding;
use std::path::Path;

const MAGIC: &[(&[u8], FileType)] = &[
    (b"MZ", FileType::BinaryPe),
    (b"\x7fELF", FileType::BinaryElf),
    (b"\xfe\xed\xfa", FileType::BinaryMachO),
    (b"PK\x03\x04", FileType::Archive),
    (b"%PDF", FileType::Document),
    (b"\x89PNG", FileType::Document),
    (b"\xff\xd8\xff", FileType::Document),
];

/// Carve embedded files from `bytes`. Returns (offset, type, bytes).
pub fn carve(bytes: &[u8]) -> Vec<(usize, FileType, Vec<u8>)> {
    let mut out = Vec::new();
    // Search for each magic at offsets > 0.
    for &(magic, ft) in MAGIC {
        let mut start = 0;
        while let Some(pos) = find_bytes(bytes, magic, start) {
            if pos > 0 {
                // Extract from pos to end (or next magic). Use to end for simplicity, cap at 5MB.
                let end = (pos + 5 * 1024 * 1024).min(bytes.len());
                let chunk = bytes[pos..end].to_vec();
                // Only if chunk differs from whole file.
                if chunk.len() < bytes.len() {
                    out.push((pos, ft, chunk));
                }
            }
            start = pos + 1;
            if start >= bytes.len() {
                break;
            }
        }
    }
    out
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

/// Scan carved embedded payloads, tagging findings as polyglot.
pub fn scan_carved(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (off, _ft, chunk) in carve(bytes) {
        let mut subs = scan::scan_bytes(path, &chunk);
        for f in &mut subs {
            f.message = format!("[carved@{}] {}", off, f.message);
            f.tags.push("polyglot".to_string());
            f.tags.push("carved".to_string());
        }
        out.extend(subs);
    }
    out
}
