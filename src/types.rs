use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Severity> {
        match value.trim().to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "moderate" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" | "informational" => Some(Severity::Info),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub confidence: f32,
    pub rule: String,
    pub category: String,
    pub location: Location,
    pub message: String,
    pub snippet: Option<String>,
    pub tags: Vec<String>,
}

/// Current report schema version. Additive changes bump the minor component.
pub const SCHEMA_VERSION: &str = "2.0";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxReport {
    pub command: String,
    pub image: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub files_created: Vec<String>,
    pub files_modified: Vec<String>,
    pub files_deleted: Vec<String>,
    pub network_indicators: Vec<String>,
    /// Backend actually used, e.g. `docker`, `linux-native`, `windows-native`.
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub policy: crate::sandbox::policy::SandboxPolicy,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub telemetry_degraded: bool,
    #[serde(default)]
    pub process_tree: Vec<crate::sandbox::telemetry::ProcessEvent>,
    #[serde(default)]
    pub syscalls: Vec<crate::sandbox::telemetry::SyscallEvent>,
    #[serde(default)]
    pub network_events: Vec<crate::sandbox::telemetry::NetworkEvent>,
    #[serde(default)]
    pub registry_changes: Vec<crate::sandbox::telemetry::RegistryChange>,
    #[serde(default)]
    pub memory_dumps: Vec<crate::sandbox::telemetry::MemoryDump>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Safe,
    Review,
    Unsafe,
    Block,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Safe => "SAFE",
            Verdict::Review => "REVIEW",
            Verdict::Unsafe => "UNSAFE",
            Verdict::Block => "BLOCK",
        }
    }
}
