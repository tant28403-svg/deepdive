//! WebAssembly import analysis. Flags host functions that grant filesystem or
//! network access, plus a few conventionally dangerous names.

use crate::types::{Finding, Location, Severity};
use std::path::Path;
use wasmparser::{Parser, Payload};

pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for payload in Parser::new(0).parse_all(bytes).flatten() {
        let Payload::ImportSection(reader) = payload else {
            continue;
        };
        for group in reader.into_iter().flatten() {
            let mut consider = |module: &str, name: &str| {
                let Some((rule, severity, confidence, message)) = classify(module, name) else {
                    return;
                };
                let key = format!("{}:{}:{}", rule, module, name);
                if !seen.insert(key) {
                    return;
                }
                findings.push(Finding {
                    id: format!("{}-{}-{}", rule, module, name),
                    severity,
                    confidence,
                    rule: rule.to_string(),
                    category: "wasm".to_string(),
                    location: Location {
                        path: path.to_string_lossy().to_string(),
                        line: None,
                        column: None,
                    },
                    message: format!("{} ({}.{})", message, module, name),
                    snippet: Some(format!("{}::{}", module, name)),
                    tags: vec!["wasm".to_string()],
                });
            };
            match group {
                wasmparser::Imports::Single(_, import) => consider(import.module, import.name),
                wasmparser::Imports::Compact1 { module, items } => {
                    for item in items.into_iter().flatten() {
                        consider(module, item.name);
                    }
                }
                wasmparser::Imports::Compact2 { module, names, .. } => {
                    for name in names.into_iter().flatten() {
                        consider(module, name);
                    }
                }
            }
        }
    }

    findings
}

#[allow(clippy::type_complexity)]
fn classify(module: &str, name: &str) -> Option<(&'static str, Severity, f32, &'static str)> {
    let wasi = module.starts_with("wasi");
    if wasi && name.starts_with("sock_") {
        return Some((
            "wasm.wasi-network",
            Severity::High,
            0.6,
            "WASI import grants network access",
        ));
    }
    if wasi && (name.starts_with("path_") || name.starts_with("fd_")) {
        return Some((
            "wasm.wasi-filesystem",
            Severity::Medium,
            0.5,
            "WASI import grants filesystem access",
        ));
    }
    if matches!((module, name), ("env", "exec" | "eval" | "system" | "run")) {
        return Some((
            "wasm.dangerous-host-function",
            Severity::High,
            0.5,
            "WASM imports a process/script execution host function",
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Minimal wasm module importing one function.
    fn module_importing(module: &str, name: &str) -> Vec<u8> {
        let mut body = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // type section: one func type () -> ()
        body.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        // import section
        let mut import = Vec::new();
        import.push(1u8); // count
        import.extend_from_slice(&(module.len() as u8).to_be_bytes());
        import.extend_from_slice(module.as_bytes());
        import.extend_from_slice(&(name.len() as u8).to_be_bytes());
        import.extend_from_slice(name.as_bytes());
        import.push(0x00); // func
        import.push(0x00); // type index
        body.push(0x02);
        body.push(import.len() as u8);
        body.extend_from_slice(&import);
        body
    }

    #[test]
    fn flags_wasi_network_import() {
        let wasm = module_importing("wasi_snapshot_preview1", "sock_open");
        let findings = scan(&PathBuf::from("m.wasm"), &wasm);
        assert!(findings.iter().any(|f| f.rule == "wasm.wasi-network"));
    }

    #[test]
    fn flags_dangerous_env_import() {
        let wasm = module_importing("env", "eval");
        let findings = scan(&PathBuf::from("m.wasm"), &wasm);
        assert!(findings
            .iter()
            .any(|f| f.rule == "wasm.dangerous-host-function"));
    }

    #[test]
    fn benign_import_is_quiet() {
        let wasm = module_importing("env", "memory_grow");
        assert!(scan(&PathBuf::from("m.wasm"), &wasm).is_empty());
    }
}
