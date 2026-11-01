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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
