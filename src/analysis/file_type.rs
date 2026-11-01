// Magic-byte file type detection (later stage).
pub enum FileType {
    Unknown,
    Source,
    Binary,
    Archive,
    Document,
    Config,
}
