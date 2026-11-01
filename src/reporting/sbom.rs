use crate::analysis::deps::Dependency;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Render a CycloneDX 1.5 JSON document for the given dependencies.
pub fn cyclonedx(deps: &[Dependency], root: &Path) -> String {
    let deps = unique(deps);
    let name = root_name(root);
    let timestamp = rfc3339_now();
    let serial = urn_uuid(&format!("{}:{}", root.display(), timestamp));

    let components: Vec<serde_json::Value> = deps
        .iter()
        .map(|dep| {
            let purl = purl(dep);
            serde_json::json!({
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": purl,
                "bom-ref": format!("{}@{}", dep.name, dep.version),
                "scope": "required",
            })
        })
        .collect();

    let document = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "deepdive",
                    "version": env!("CARGO_PKG_VERSION"),
                }]
            },
            "component": {
                "type": "application",
                "name": name,
                "bom-ref": name,
            }
        },
        "components": components,
    });

    serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
}

/// Render an SPDX 2.3 JSON document for the given dependencies.
pub fn spdx(deps: &[Dependency], root: &Path) -> String {
    let deps = unique(deps);
    let name = root_name(root);
    let created = rfc3339_now();
    let namespace = format!(
        "https://deepdive.local/spdx/{}-{}",
        slug(&name),
        &urn_uuid(&format!("{}:{}", root.display(), created))[9..]
    );

    let packages: Vec<serde_json::Value> = deps
        .iter()
        .enumerate()
        .map(|(i, dep)| {
            serde_json::json!({
                "SPDXID": format!("SPDXRef-Package-{}", i + 1),
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl(dep),
                }],
            })
        })
        .collect();

    let relationships: Vec<serde_json::Value> = (1..=deps.len())
        .map(|i| {
            serde_json::json!({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": format!("SPDXRef-Package-{}", i),
            })
        })
        .collect();

    let document = serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": [format!("Tool: deepdive-{}", env!("CARGO_PKG_VERSION"))],
        },
        "packages": packages,
        "relationships": relationships,
    });

    serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
}

/// Package URL for a dependency.
pub fn purl(dep: &Dependency) -> String {
    let (kind, name) = match dep.ecosystem.as_str() {
        "npm" => ("npm", dep.name.replace('@', "%40")),
        "cargo" => ("cargo", dep.name.clone()),
        "pypi" => ("pypi", dep.name.replace('_', "-")),
        "go" => ("golang", dep.name.clone()),
        "rubygems" => ("gem", dep.name.clone()),
        other => (other, dep.name.clone()),
    };
    if dep.version.is_empty() {
        format!("pkg:{}/{}", kind, name)
    } else {
        format!("pkg:{}/{}@{}", kind, name, dep.version)
    }
}

fn unique(deps: &[Dependency]) -> Vec<Dependency> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for dep in deps {
        let key = (dep.ecosystem.clone(), dep.name.clone(), dep.version.clone());
        if seen.insert(key) {
            out.push(dep.clone());
        }
    }
    out.sort_by(|a, b| {
        (&a.ecosystem, &a.name, &a.version).cmp(&(&b.ecosystem, &b.name, &b.version))
    });
    out
}

fn root_name(root: &Path) -> String {
    root.file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("deepdive-target")
        .to_string()
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn urn_uuid(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    let hex = hex::encode(&digest[..16]);
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// RFC 3339 UTC timestamp built without a date-time dependency.
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Convert days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn deps() -> Vec<Dependency> {
        vec![
            Dependency {
                ecosystem: "npm".to_string(),
                name: "@scope/pkg".to_string(),
                version: "1.2.3".to_string(),
                source: PathBuf::from("package-lock.json"),
            },
            Dependency {
                ecosystem: "cargo".to_string(),
                name: "serde".to_string(),
                version: "1.0.0".to_string(),
                source: PathBuf::from("Cargo.lock"),
            },
        ]
    }

    #[test]
    fn builds_purls() {
        let deps = deps();
        assert_eq!(purl(&deps[0]), "pkg:npm/%40scope/pkg@1.2.3");
        assert_eq!(purl(&deps[1]), "pkg:cargo/serde@1.0.0");
    }

    #[test]
    fn cyclonedx_document_is_valid_shape() {
        let value: serde_json::Value =
            serde_json::from_str(&cyclonedx(&deps(), Path::new("myrepo"))).unwrap();
        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(value["specVersion"], "1.5");
        assert_eq!(value["metadata"]["component"]["name"], "myrepo");
        assert_eq!(value["components"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn spdx_document_is_valid_shape() {
        let value: serde_json::Value =
            serde_json::from_str(&spdx(&deps(), Path::new("myrepo"))).unwrap();
        assert_eq!(value["spdxVersion"], "SPDX-2.3");
        assert_eq!(value["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(value["packages"].as_array().unwrap().len(), 2);
        assert_eq!(value["relationships"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn deduplicates_dependencies() {
        let mut list = deps();
        list.push(deps()[0].clone());
        let value: serde_json::Value =
            serde_json::from_str(&cyclonedx(&list, Path::new("repo"))).unwrap();
        assert_eq!(value["components"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn civil_dates_are_correct() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
    }
}
