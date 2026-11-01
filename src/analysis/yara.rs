use crate::types::Finding;
#[cfg(feature = "yara")]
use crate::types::{Location, Severity};
#[cfg(feature = "yara")]
use anyhow::Context;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Compiled YARA rules. Empty when deepdive is built without the `yara` feature.
pub struct YaraRules {
    #[cfg(feature = "yara")]
    inner: Option<yara_x::Rules>,
    #[cfg(not(feature = "yara"))]
    _private: (),
}

impl YaraRules {
    pub fn empty() -> Self {
        #[cfg(feature = "yara")]
        {
            Self { inner: None }
        }
        #[cfg(not(feature = "yara"))]
        {
            Self { _private: () }
        }
    }

    pub fn available() -> bool {
        cfg!(feature = "yara")
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "yara")]
        {
            self.inner.is_none()
        }
        #[cfg(not(feature = "yara"))]
        {
            true
        }
    }

    pub fn len(&self) -> usize {
        #[cfg(feature = "yara")]
        {
            self.inner
                .as_ref()
                .map(|rules| rules.iter().len())
                .unwrap_or(0)
        }
        #[cfg(not(feature = "yara"))]
        {
            0
        }
    }

    /// Compile YARA sources. Without the feature enabled this returns an empty set.
    pub fn compile(paths: &[PathBuf]) -> Result<Self> {
        #[cfg(not(feature = "yara"))]
        {
            if !paths.is_empty() {
                eprintln!(
                    "warning: {} YARA rule file(s) ignored; rebuild with --features yara",
                    paths.len()
                );
            }
            Ok(Self::empty())
        }
        #[cfg(feature = "yara")]
        {
            if paths.is_empty() {
                return Ok(Self::empty());
            }
            let mut compiler = yara_x::Compiler::new();
            for path in paths {
                let source = std::fs::read_to_string(path)
                    .with_context(|| format!("read YARA rule {}", path.display()))?;
                compiler.add_source(source.as_str()).map_err(|err| {
                    anyhow::anyhow!("compile YARA rule {}: {}", path.display(), err)
                })?;
            }
            Ok(Self {
                inner: Some(compiler.build()),
            })
        }
    }

    /// Scan a file's bytes and convert matching YARA rules into findings.
    pub fn scan(&self, path: &Path, bytes: &[u8]) -> Vec<Finding> {
        #[cfg(not(feature = "yara"))]
        {
            let _ = (path, bytes);
            Vec::new()
        }
        #[cfg(feature = "yara")]
        {
            let Some(rules) = &self.inner else {
                return Vec::new();
            };
            let mut scanner = yara_x::Scanner::new(rules);
            let Ok(results) = scanner.scan(bytes) else {
                return Vec::new();
            };
            let path_str = path.display().to_string();
            let mut out = Vec::new();
            for rule in results.matching_rules() {
                let identifier = rule.identifier().to_string();
                let metadata = rule.metadata().into_json();
                let severity = yara_severity(&metadata);
                let mut tags = vec!["yara".to_string()];
                tags.extend(rule.tags().map(|tag| tag.identifier().to_string()));
                let description = metadata
                    .as_array()
                    .and_then(|entries| {
                        entries.iter().find_map(|entry| {
                            let pair = entry.as_array()?;
                            if pair.first()?.as_str()? == "description" {
                                pair.get(1)?.as_str().map(|s| s.to_string())
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or_default();
                out.push(Finding {
                    id: format!("yara.{}-{}", identifier, path_str),
                    severity,
                    confidence: 0.85,
                    rule: format!("yara.{}", identifier),
                    category: "yara".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: if description.is_empty() {
                        format!("YARA rule matched: {}", identifier)
                    } else {
                        format!("YARA rule matched: {} — {}", identifier, description)
                    },
                    snippet: None,
                    tags,
                });
            }
            out
        }
    }
}

#[cfg(feature = "yara")]
fn yara_severity(metadata: &serde_json::Value) -> Severity {
    let level = metadata.as_array().and_then(|entries| {
        entries.iter().find_map(|entry| {
            let pair = entry.as_array()?;
            if pair.first()?.as_str()? == "severity" {
                pair.get(1)?.as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    });
    level
        .as_deref()
        .and_then(Severity::parse)
        .unwrap_or(Severity::High)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rules_are_safe() {
        let rules = YaraRules::empty();
        assert!(rules.is_empty());
        assert_eq!(rules.len(), 0);
        assert!(rules.scan(Path::new("x.bin"), b"test").is_empty());
    }

    #[cfg(feature = "yara")]
    #[test]
    fn compiles_and_matches_yara_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yar");
        std::fs::write(
            &path,
            r#"
rule test_payload {
  meta:
    severity = "critical"
    description = "test marker"
  strings:
    $a = "deepdive-test-marker"
  condition:
    $a
}
"#,
        )
        .unwrap();
        let rules = YaraRules::compile(&[path]).unwrap();
        assert_eq!(rules.len(), 1);
        let findings = rules.scan(Path::new("sample.bin"), b"xx deepdive-test-marker xx");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].rule, "yara.test_payload");
    }
}
