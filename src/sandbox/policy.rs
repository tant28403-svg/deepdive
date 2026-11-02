use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Which sandbox engine to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Prefer Docker when available, otherwise the native backend.
    #[default]
    Auto,
    /// Native OS isolation (namespaces on Linux, job objects/token on Windows).
    Native,
    /// Docker container.
    Docker,
    /// Do not run a sandbox.
    None,
}

impl Backend {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Backend::Auto),
            "native" => Some(Backend::Native),
            "docker" => Some(Backend::Docker),
            "none" => Some(Backend::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Auto => "auto",
            Backend::Native => "native",
            Backend::Docker => "docker",
            Backend::None => "none",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the sandboxed process may use the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    /// No network access at all.
    #[default]
    None,
    /// Network redirected through the capture proxy (stage 20).
    Capture,
    /// Unrestricted network access.
    Allow,
}

impl NetworkPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkPolicy::None => "none",
            NetworkPolicy::Capture => "capture",
            NetworkPolicy::Allow => "allow",
        }
    }
}

/// Everything a backend needs to know about how to isolate a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub backend: Backend,
    pub network: NetworkPolicy,
    pub timeout_secs: u64,
    pub memory_mb: u64,
    pub cpus: f32,
    pub pids: u32,
    pub read_only_root: bool,
    /// Extra host paths to expose read-write inside the sandbox.
    #[serde(default)]
    pub writable: Vec<PathBuf>,
    pub env_scrub: bool,
    /// Number of anti-analysis comparison runs (stage 20).
    pub runs: u8,
    pub trace: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            backend: Backend::Auto,
            network: NetworkPolicy::None,
            timeout_secs: 300,
            memory_mb: 512,
            cpus: 1.0,
            pids: 256,
            read_only_root: true,
            writable: Vec::new(),
            env_scrub: true,
            runs: 1,
            trace: false,
        }
    }
}

impl SandboxPolicy {
    /// Parse a preset name or a path to a TOML policy file.
    pub fn from_spec(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(Self::default());
        }
        let preset = match spec.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::default()),
            "network-capture" => Some(Self {
                network: NetworkPolicy::Capture,
                ..Self::default()
            }),
            "permissive" => Some(Self {
                network: NetworkPolicy::Allow,
                read_only_root: false,
                env_scrub: false,
                ..Self::default()
            }),
            _ => None,
        };
        if let Some(policy) = preset {
            return Ok(policy);
        }
        if Path::new(spec).is_file() {
            let content = std::fs::read_to_string(spec)
                .with_context(|| format!("read sandbox policy {}", spec))?;
            let policy: SandboxPolicy = toml::from_str(&content)
                .with_context(|| format!("parse sandbox policy {}", spec))?;
            return Ok(policy);
        }
        bail!(
            "unknown sandbox policy '{}' (expected strict, network-capture, permissive, or a TOML file)",
            spec
        );
    }

    pub fn with_backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }

    pub fn network_label(&self) -> &'static str {
        self.network.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_backends() {
        assert_eq!(Backend::parse("AUTO"), Some(Backend::Auto));
        assert_eq!(Backend::parse("native"), Some(Backend::Native));
        assert_eq!(Backend::parse("nope"), None);
    }

    #[test]
    fn parses_presets() {
        let strict = SandboxPolicy::from_spec("strict").unwrap();
        assert_eq!(strict.network, NetworkPolicy::None);
        assert!(strict.read_only_root);

        let capture = SandboxPolicy::from_spec("network-capture").unwrap();
        assert_eq!(capture.network, NetworkPolicy::Capture);

        let permissive = SandboxPolicy::from_spec("permissive").unwrap();
        assert_eq!(permissive.network, NetworkPolicy::Allow);
        assert!(!permissive.read_only_root);

        assert!(SandboxPolicy::from_spec("does-not-exist").is_err());
    }
}
