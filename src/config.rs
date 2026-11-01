use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub min_severity: Option<String>,
    pub offline: Option<bool>,
    pub rules: Vec<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        // Look in XDG config dir / %APPDATA%
        let config_dir = directories::ProjectDirs::from("", "", "deepdive")
            .map(|d| d.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let path = config_dir.join("config.toml");
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(toml::from_str(&content)?)
        } else {
            Ok(Config::default())
        }
    }
}
