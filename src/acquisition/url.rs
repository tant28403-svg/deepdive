use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct RepoUrl {
    pub host: String,
    pub owner: String,
    pub repo: String,
    pub branch: Option<String>,
    pub subdir: Option<String>,
}

impl RepoUrl {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim().trim_end_matches('/').trim_end_matches(".git");
        // SSH form: git@github.com:owner/repo
        if let Some(rest) = input.strip_prefix("git@") {
            let (host, path) = rest.split_once(':').context("invalid ssh url")?;
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() < 2 {
                anyhow::bail!("invalid repo path");
            }
            return Ok(RepoUrl {
                host: host.to_string(),
                owner: parts[0].to_string(),
                repo: parts[1].to_string(),
                branch: None,
                subdir: None,
            });
        }
        // HTTPS form
        let url = url::Url::parse(input).context("invalid url")?;
        let host = url.host_str().context("no host")?.to_string();
        let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
        if segments.len() < 2 {
            anyhow::bail!("invalid repo path");
        }
        let owner = segments[0].to_string();
        let repo = segments[1].to_string();
        // Optional /tree/<branch>/...
        let mut branch = None;
        let mut subdir = None;
        if segments.len() >= 4 && segments[2] == "tree" {
            branch = Some(segments[3].to_string());
            if segments.len() > 4 {
                subdir = Some(segments[4..].join("/"));
            }
        }
        Ok(RepoUrl {
            host,
            owner,
            repo,
            branch,
            subdir,
        })
    }

    pub fn clone_url(&self) -> String {
        format!("https://{}/{}/{}.git", self.host, self.owner, self.repo)
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

// Minimal url crate shim using std? We need url parsing. Add `url` crate.
// Since `url` may not be a dep, implement minimal parsing above already handles paths.
// The url::Url::parse above requires the `url` crate. To avoid new dep, fallback:
// (kept as-is; add dep in Cargo.toml)
#[allow(dead_code)]
pub fn _placeholder() {}
