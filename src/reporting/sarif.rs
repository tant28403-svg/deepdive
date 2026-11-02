use crate::types::Finding;
use serde_json::json;
use std::collections::BTreeMap;

pub fn render(findings: &[Finding], files_scanned: usize, tool_version: &str) -> String {
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule,
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.path },
                        "region": {
                            "startLine": f.location.line.unwrap_or(1),
                            "startColumn": f.location.column.unwrap_or(1)
                        }
                    }
                }]
            })
        })
        .collect();

    // Build unique rule definitions from findings
    let mut rules_map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for f in findings {
        if !rules_map.contains_key(&f.rule) {
            rules_map.insert(
                f.rule.clone(),
                json!({
                    "id": f.rule,
                    "name": f.rule,
                    "shortDescription": { "text": f.message.chars().take(120).collect::<String>() },
                    "fullDescription": { "text": f.message },
                    "defaultConfiguration": { "level": sarif_level(f.severity) },
                    "properties": {
                        "category": f.category,
                        "severity": f.severity.as_str(),
                    }
                }),
            );
        }
    }
    let rules: Vec<_> = rules_map.into_values().collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "deepdive",
                    "version": tool_version,
                    "informationUri": "https://github.com/tant28403-svg/deepdive",
                    "rules": rules
                }
            },
            "results": results,
            "properties": {
                "filesScanned": files_scanned
            }
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

fn sarif_level(s: crate::types::Severity) -> &'static str {
    use crate::types::Severity;
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
