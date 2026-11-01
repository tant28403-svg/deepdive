use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: String, // "npm", "cargo", "pypi", "go"
    pub name: String,
    pub version: String,
    pub source: PathBuf,
}

pub mod integrity;
pub mod osv;
pub mod parsers;

pub use integrity::scan as scan_integrity;
pub use osv::audit_dependencies;
pub use parsers::collect_dependencies;

#[cfg(test)]
mod tests {
    use super::parsers::*;

    #[test]
    fn parse_npm_lock_basic() {
        let content = r#"{
  "name": "x",
  "lockfileVersion": 2,
  "packages": {
    "": { "name": "x", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/express": { "version": "4.18.2" }
  }
}"#;
        let deps = parse_npm_lock(content, std::path::Path::new("package-lock.json"));
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "lodash" && d.version == "4.17.21"));
    }

    #[test]
    fn parse_cargo_lock_basic() {
        let content = r#"[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let deps = parse_cargo_lock(content, std::path::Path::new("Cargo.lock"));
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "serde"));
    }

    #[test]
    fn parse_requirements_basic() {
        let content = "requests==2.31.0\nflask>=2.0\n# comment\nnumpy\n";
        let deps = parse_requirements(content, std::path::Path::new("requirements.txt"));
        assert_eq!(deps.len(), 3);
    }
}
