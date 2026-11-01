use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Unknown,
    Source,
    Script,
    BinaryElf,
    BinaryPe,
    BinaryMachO,
    Archive,
    Document,
    Config,
    Text,
}

impl FileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileType::Unknown => "unknown",
            FileType::Source => "source",
            FileType::Script => "script",
            FileType::BinaryElf => "binary-elf",
            FileType::BinaryPe => "binary-pe",
            FileType::BinaryMachO => "binary-macho",
            FileType::Archive => "archive",
            FileType::Document => "document",
            FileType::Config => "config",
            FileType::Text => "text",
        }
    }
}

/// Detect file type from magic bytes (and extension fallback).
pub fn detect(path: &Path) -> FileType {
    let Ok(meta) = fs::metadata(path) else {
        return FileType::Unknown;
    };
    if meta.is_dir() {
        return FileType::Unknown;
    }
    // Read first 64 bytes.
    let Ok(bytes) = fs::read(path) else {
        return FileType::Unknown;
    };
    detect_bytes(&bytes, path)
}

pub fn detect_bytes(bytes: &[u8], path: &Path) -> FileType {
    if bytes.len() >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A {
        return FileType::BinaryPe;
    }
    if bytes.len() >= 4
        && bytes[0] == 0x7F
        && bytes[1] == 0x45
        && bytes[2] == 0x4C
        && bytes[3] == 0x46
    {
        return FileType::BinaryElf;
    }
    // Mach-O
    if bytes.len() >= 4 {
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCEFAEDFE || magic == 0xCFFAEDFE
        {
            return FileType::BinaryMachO;
        }
    }
    // ZIP (also Office/Java)
    if bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4B
        && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07)
    {
        // Could be Office (zip with [Content_Types].xml) — treat as archive; document detection later.
        return FileType::Archive;
    }
    // 7z
    if bytes.len() >= 6
        && bytes[0] == 0x37
        && bytes[1] == 0x7A
        && bytes[2] == 0xBC
        && bytes[3] == 0xAF
    {
        return FileType::Archive;
    }
    // RAR
    if bytes.len() >= 6
        && bytes[0] == 0x52
        && bytes[1] == 0x61
        && bytes[2] == 0x72
        && bytes[3] == 0x21
    {
        return FileType::Archive;
    }
    // Gzip
    if bytes.len() >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B {
        return FileType::Archive;
    }
    // PDF
    if bytes.len() >= 4
        && bytes[0] == 0x25
        && bytes[1] == 0x50
        && bytes[2] == 0x44
        && bytes[3] == 0x46
    {
        return FileType::Document;
    }
    // PNG
    if bytes.len() >= 8 && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return FileType::Document;
    }
    // JPEG
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        return FileType::Document;
    }

    // Text / source heuristic: valid UTF-8 and mostly printable.
    if std::str::from_utf8(bytes).is_ok() {
        // extension-based refinement
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        match ext.as_str() {
            "rs" | "go" | "c" | "cpp" | "cc" | "h" | "hpp" | "java" | "kt" | "swift" | "js"
            | "ts" | "tsx" | "jsx" | "py" | "rb" | "php" | "pl" | "lua" | "scala" | "hs" | "ml"
            | "cs" | "fs" | "vb" => {
                return FileType::Source;
            }
            "sh" | "bash" | "zsh" | "fish" | "ps1" | "bat" | "cmd" | "vbs" | "jse" | "wsf"
            | "hta" => {
                return FileType::Script;
            }
            "json" | "yaml" | "yml" | "toml" | "xml" | "ini" | "env" | "properties"
            | "dockerfile" | "tf" | "hcl" => {
                return FileType::Config;
            }
            "md" | "txt" | "rst" | "adoc" => {
                return FileType::Text;
            }
            _ => {}
        }
        // If mostly printable, treat as text.
        let printable = bytes
            .iter()
            .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
        if bytes.is_empty() || printable as f64 / bytes.len() as f64 > 0.85 {
            return FileType::Text;
        }
    }
    FileType::Unknown
}
