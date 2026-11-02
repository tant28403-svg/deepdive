/// Typed sandbox failures so callers can distinguish "not installed" from a real
/// execution failure and degrade gracefully.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Unsupported/Permission are used by the platform-specific backends.
pub enum SandboxError {
    #[error("sandbox backend unavailable: {0}")]
    Unavailable(String),
    #[error("sandbox backend not supported on this platform: {0}")]
    Unsupported(String),
    #[error("sandbox permission denied: {0}")]
    Permission(String),
    #[error("sandbox io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
