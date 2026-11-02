//! Carve embedded filesystem images (SquashFS, JFFS2, UBI, ext, cramfs) from
//! firmware dumps. Extraction is out of scope; this reports what is present
//! and how dense the region looks.

use crate::types::{Finding, Location, Severity};
use std::path::Path;

const MAX_ENTROPY_WINDOW: usize = 1024 * 1024;

struct Signature {
    magic: &'static [u8],
    kind: &'static str,
    /// Minimum file size before the signature is trusted.
    min_size: usize,
}

const SIGNATURES: &[Signature] = &[
    Signature {
        magic: b"hsqs",
        kind: "squashfs",
        min_size: 1024,
    },
    Signature {
        magic: b"sqsh",
        kind: "squashfs-be",
        min_size: 1024,
    },
    Signature {
        magic: b"UBI#",
        kind: "ubi",
        min_size: 1024,
    },
    Signature {
        magic: &[0x85, 0x19],
        kind: "jffs2",
        min_size: 1024,
    },
    Signature {
        magic: b"Compressed ROMFS",
        kind: "cramfs",
        min_size: 1024,
    },
];

const EXT_MAGIC: [u8; 2] = [0x53, 0xEF];
const EXT_SUPERBLOCK_OFFSET: usize = 0x438;

pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    if bytes.len() < 1024 {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for signature in SIGNATURES {
        if bytes.len() < signature.min_size {
            continue;
        }
        let Some(offset) = find(bytes, signature.magic) else {
            continue;
        };
        findings.push(finding(path, signature.kind, offset, bytes));
    }

    if bytes.len() >= EXT_SUPERBLOCK_OFFSET + 2
        && bytes[EXT_SUPERBLOCK_OFFSET..EXT_SUPERBLOCK_OFFSET + 2] == EXT_MAGIC
    {
        findings.push(finding(path, "ext", EXT_SUPERBLOCK_OFFSET, bytes));
    }

    findings
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn finding(path: &Path, kind: &str, offset: usize, bytes: &[u8]) -> Finding {
    let window_end = (offset + MAX_ENTROPY_WINDOW).min(bytes.len());
    let density = entropy(&bytes[offset..window_end]);
    Finding {
        id: format!("firmware.carved-image-{}", kind),
        severity: Severity::Medium,
        confidence: 0.6,
        rule: "firmware.carved-image".to_string(),
        category: "firmware".to_string(),
        location: Location {
            path: path.to_string_lossy().to_string(),
            line: None,
            column: None,
        },
        message: format!(
            "Embedded {} filesystem image at offset 0x{:x} (region entropy {:.2})",
            kind, offset, density
        ),
        snippet: Some(kind.to_string()),
        tags: vec!["firmware".to_string()],
    }
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn carves_squashfs_and_ext() {
        let mut bytes = vec![0u8; 4096];
        bytes[100..104].copy_from_slice(b"hsqs");
        bytes[EXT_SUPERBLOCK_OFFSET..EXT_SUPERBLOCK_OFFSET + 2].copy_from_slice(&EXT_MAGIC);

        let findings = scan(&PathBuf::from("firmware.bin"), &bytes);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.rule == "firmware.carved-image"));
        assert!(findings.iter().any(|f| f.message.contains("squashfs")));
        assert!(findings.iter().any(|f| f.message.contains("ext")));
    }

    #[test]
    fn small_files_are_ignored() {
        let bytes = b"hsqs";
        assert!(scan(&PathBuf::from("tiny.bin"), bytes).is_empty());
    }

    #[test]
    fn plain_data_is_quiet() {
        let bytes = vec![0x41u8; 8192];
        assert!(scan(&PathBuf::from("blob.bin"), &bytes).is_empty());
    }
}
