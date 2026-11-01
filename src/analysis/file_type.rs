use std::fs;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Unknown,
    Source,
    Script,
    Text,
    Config,
    BinaryElf,
    BinaryPe,
    BinaryMachO,
    Archive,
    Document,
    /// JVM bytecode (.class), WebAssembly, or a JVM archive (.jar/.war/.apk).
    Bytecode,
    /// Windows artifacts: .lnk shortcuts, .reg exports, .msi installers, task XML.
    WindowsArtifact,
    /// SQLite databases and similar local data stores.
    Database,
    /// OS package formats: .deb, .rpm.
    Package,
}

impl FileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileType::Unknown => "unknown",
            FileType::Source => "source",
            FileType::Script => "script",
            FileType::Text => "text",
            FileType::Config => "config",
            FileType::BinaryElf => "binary-elf",
            FileType::BinaryPe => "binary-pe",
            FileType::BinaryMachO => "binary-macho",
            FileType::Archive => "archive",
            FileType::Document => "document",
            FileType::Bytecode => "bytecode",
            FileType::WindowsArtifact => "windows-artifact",
            FileType::Database => "database",
            FileType::Package => "package",
        }
    }
}

/// Detect file type from magic bytes (and extension fallback).
pub fn detect(path: &Path) -> FileType {
    let Ok(file) = fs::File::open(path) else {
        return FileType::Unknown;
    };
    // 64 KiB is enough for ISO magic at 0x8001 and tar magic at 257.
    let mut bytes = Vec::new();
    if file.take(64 * 1024).read_to_end(&mut bytes).is_err() {
        return FileType::Unknown;
    }
    detect_bytes(&bytes, path)
}

pub fn detect_bytes(bytes: &[u8], path: &Path) -> FileType {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // --- Executables / bytecode ---
    if bytes.len() >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A {
        return FileType::BinaryPe;
    }
    if bytes.len() >= 4 && bytes[0..4] == [0x7F, 0x45, 0x4C, 0x46] {
        return FileType::BinaryElf;
    }
    if bytes.len() >= 8 && bytes[0..8] == [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00] {
        return FileType::Bytecode;
    }
    if bytes.len() >= 4 {
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCEFAEDFE || magic == 0xCFFAEDFE
        {
            return FileType::BinaryMachO;
        }
        // 0xCAFEBABE is shared by Java class files and fat Mach-O binaries.
        if magic == 0xCAFEBABE || magic == 0xCAFEBABF {
            let java_major = u16::from_be_bytes([bytes[6], bytes[7]]);
            if magic == 0xCAFEBABE && (45..=100).contains(&java_major) {
                return FileType::Bytecode;
            }
            return FileType::BinaryMachO;
        }
    }

    // --- Windows artifacts ---
    if bytes.len() >= 8 && bytes[0..8] == [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] {
        return FileType::WindowsArtifact;
    }
    if bytes.len() >= 8 && bytes[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        // Compound File Binary: legacy Office documents or MSI installers.
        return match ext.as_str() {
            "msi" | "msp" | "mst" => FileType::WindowsArtifact,
            _ => FileType::Document,
        };
    }
    if ext == "lnk" {
        return FileType::WindowsArtifact;
    }
    if ext == "reg" {
        return FileType::WindowsArtifact;
    }

    // --- Databases ---
    if bytes.starts_with(b"SQLite format 3\0") {
        return FileType::Database;
    }

    // --- OS packages ---
    if bytes.starts_with(b"!<arch>\n") {
        return FileType::Package;
    }
    if bytes.len() >= 4 && bytes[0..4] == [0xED, 0xAB, 0xEE, 0xDB] {
        return FileType::Package;
    }

    // --- Archives ---
    if bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4B
        && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07)
    {
        // JVM/Android archives are zip containers with bytecode inside.
        if matches!(ext.as_str(), "jar" | "war" | "ear" | "apk" | "aar") {
            return FileType::Bytecode;
        }
        return FileType::Archive;
    }
    if bytes.len() >= 6 && bytes[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return FileType::Archive;
    }
    if bytes.len() >= 4 && bytes[0..4] == [0x52, 0x61, 0x72, 0x21] {
        return FileType::Archive;
    }
    if bytes.len() >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B {
        return FileType::Archive;
    }
    if bytes.len() >= 6 && bytes[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        return FileType::Archive;
    }
    if bytes.len() >= 3 && bytes[0..3] == [0x42, 0x5A, 0x68] {
        return FileType::Archive;
    }
    if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
        return FileType::Archive;
    }
    if bytes.len() > 0x8005 && &bytes[0x8001..0x8005] == b"CD001" {
        return FileType::Archive;
    }

    // --- Documents / media ---
    if bytes.len() >= 4 && bytes[0..4] == [0x25, 0x50, 0x44, 0x46] {
        return FileType::Document;
    }
    if bytes.len() >= 8 && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return FileType::Document;
    }
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        return FileType::Document;
    }
    if bytes.len() >= 6 && (&bytes[0..6] == b"GIF87a" || &bytes[0..6] == b"GIF89a") {
        return FileType::Document;
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return FileType::Document;
    }
    if bytes.len() >= 2 && bytes[0] == 0x42 && bytes[1] == 0x4D && ext == "bmp" {
        return FileType::Document;
    }

    // --- Text encodings ---
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return ext_refine(&ext, FileType::Text);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let lower = text.to_lowercase();
        if lower.contains("windows registry editor version") || text.starts_with("REGEDIT4") {
            return FileType::WindowsArtifact;
        }
        if lower.contains("<task ")
            && lower.contains("schemas.microsoft.com/windows/2004/02/mit/task")
        {
            return FileType::WindowsArtifact;
        }
        return ext_refine(&ext, FileType::Text);
    }

    // Mostly printable fallback.
    let printable = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    if !bytes.is_empty() && printable as f64 / bytes.len() as f64 > 0.85 {
        return ext_refine(&ext, FileType::Text);
    }
    FileType::Unknown
}

fn ext_refine(ext: &str, fallback: FileType) -> FileType {
    match ext {
        "rs" | "go" | "c" | "cpp" | "cc" | "cxx" | "h" | "hpp" | "java" | "kt" | "kts"
        | "swift" | "js" | "ts" | "tsx" | "jsx" | "mjs" | "cjs" | "py" | "rb" | "php" | "pl"
        | "lua" | "scala" | "hs" | "ml" | "cs" | "fs" | "vb" | "dart" | "ex" | "exs" | "erl"
        | "clj" | "groovy" | "sol" | "asm" | "s" => FileType::Source,
        "sh" | "bash" | "zsh" | "fish" | "ps1" | "psm1" | "bat" | "cmd" | "vbs" | "vbe" | "jse"
        | "wsf" | "wsh" | "hta" | "pyw" => FileType::Script,
        "json" | "json5" | "jsonc" | "yaml" | "yml" | "toml" | "xml" | "ini" | "cfg" | "conf"
        | "env" | "properties" | "dockerfile" | "tf" | "hcl" | "csproj" | "vbproj" | "fsproj"
        | "sln" | "gradle" | "cmake" | "mk" => FileType::Config,
        "md" | "txt" | "rst" | "adoc" | "log" | "csv" | "tsv" => FileType::Text,
        "jar" | "war" | "ear" | "apk" | "aar" | "class" | "wasm" => FileType::Bytecode,
        "msi" | "msp" | "mst" | "lnk" | "reg" => FileType::WindowsArtifact,
        "sqlite" | "sqlite3" | "db" | "db3" => FileType::Database,
        "deb" | "rpm" => FileType::Package,
        "zip" | "tar" | "gz" | "tgz" | "xz" | "bz2" | "7z" | "rar" | "iso" | "cab" => {
            FileType::Archive
        }
        "pdf" | "doc" | "xls" | "ppt" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp"
        | "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "svg" | "html" | "htm" | "ipynb" => {
            FileType::Document
        }
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn detect_named(bytes: &[u8], name: &str) -> FileType {
        detect_bytes(bytes, &PathBuf::from(name))
    }

    #[test]
    fn detects_windows_and_bytecode_magics() {
        assert_eq!(
            detect_named(&[0x4C, 0, 0, 0, 1, 0x14, 2, 0], "x.lnk"),
            FileType::WindowsArtifact
        );
        assert_eq!(
            detect_named(
                &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
                "setup.msi"
            ),
            FileType::WindowsArtifact
        );
        assert_eq!(
            detect_named(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0, 0, 0], "m.wasm"),
            FileType::Bytecode
        );
        let mut class = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37];
        class.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_named(&class, "A.class"), FileType::Bytecode);
        let mut fat = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        fat.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_named(&fat, "fat.bin"), FileType::BinaryMachO);
    }

    #[test]
    fn detects_databases_and_packages() {
        assert_eq!(
            detect_named(b"SQLite format 3\0rest", "cache.db"),
            FileType::Database
        );
        assert_eq!(
            detect_named(b"!<arch>\ndebian", "pkg.deb"),
            FileType::Package
        );
        assert_eq!(
            detect_named(&[0xED, 0xAB, 0xEE, 0xDB], "pkg.rpm"),
            FileType::Package
        );
    }

    #[test]
    fn detects_utf16_text() {
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in "eval(1)".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(detect_named(&utf16, "script.js"), FileType::Source);
    }

    #[test]
    fn detects_scheduled_task_xml() {
        let xml = br#"<?xml version="1.0"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions/></Task>"#;
        assert_eq!(detect_named(xml, "task.xml"), FileType::WindowsArtifact);
    }

    #[test]
    fn detects_jar_as_bytecode() {
        let zip = [0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0];
        assert_eq!(detect_named(&zip, "app.jar"), FileType::Bytecode);
        assert_eq!(detect_named(&zip, "bundle.zip"), FileType::Archive);
    }
}
