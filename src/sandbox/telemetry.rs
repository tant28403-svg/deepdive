use serde::{Deserialize, Serialize};

/// A process observed inside the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub kind: ProcessEventKind,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProcessEventKind {
    #[default]
    Spawn,
    Exit,
    Unknown,
}

impl Default for ProcessEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            parent_pid: None,
            image: None,
            command_line: None,
            kind: ProcessEventKind::Spawn,
            timestamp_ms: 0,
        }
    }
}

/// A syscall recorded by the Linux tracer or mapped from Windows ETW.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyscallEvent {
    pub pid: u32,
    pub name: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub result: Option<i64>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkEventKind {
    #[default]
    Connect,
    Dns,
    HttpRequest,
    DnsTunnel,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkEvent {
    pub pid: Option<u32>,
    pub kind: NetworkEventKind,
    pub destination: String,
    pub port: Option<u16>,
    pub detail: Option<String>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RegistryChangeKind {
    #[default]
    Modified,
    Created,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryChange {
    pub key: String,
    pub value: Option<String>,
    pub kind: RegistryChangeKind,
    pub timestamp_ms: u64,
}

/// A memory region dumped from a sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryDump {
    pub pid: u32,
    pub address: String,
    pub size: u64,
    pub path: String,
    pub sha256: String,
    pub reason: String,
}
