use crate::types::{Finding, Location, Severity};
use std::path::Path;

pub fn scan_ast(path: &Path, content: &str) -> Vec<Finding> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "js" | "jsx" | "mjs" | "cjs" => scan_js(path, content, false),
        "ts" | "tsx" => scan_js(path, content, true),
        "py" => scan_python(path, content),
        _ => Vec::new(),
    }
}

fn scan_js(path: &Path, content: &str, typescript: bool) -> Vec<Finding> {
    let mut parser = tree_sitter::Parser::new();
    let lang: tree_sitter::Language = if typescript {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    } else {
        tree_sitter_javascript::LANGUAGE.into()
    };
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(content, None) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let path_str = path.display().to_string();
    walk_js(tree.root_node(), content, &path_str, &mut out);
    out
}

fn walk_js(node: tree_sitter::Node, content: &str, path_str: &str, out: &mut Vec<Finding>) {
    // Detect call expressions.
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let func_text = func.utf8_text(content.as_bytes()).unwrap_or("");
            let dangerous = func_text == "eval"
                || func_text.ends_with(".exec")
                || func_text.ends_with(".spawn")
                || func_text == "exec"
                || func_text.ends_with("execSync")
                || func_text.ends_with("spawnSync");
            if dangerous {
                let row = node.start_position().row + 1;
                out.push(Finding {
                    id: format!("ast.js-dangerous-call-{}-{}", path_str, row),
                    severity: Severity::High,
                    confidence: 0.85,
                    rule: "ast.js-dangerous-call".to_string(),
                    category: "ast".to_string(),
                    location: Location {
                        path: path_str.to_string(),
                        line: Some(row),
                        column: Some(node.start_position().column + 1),
                    },
                    message: format!("AST: dangerous call '{}'", func_text),
                    snippet: node
                        .utf8_text(content.as_bytes())
                        .ok()
                        .map(|s| s.chars().take(120).collect()),
                    tags: vec!["ast".to_string(), "javascript".to_string()],
                });
            }
            // child_process require
            if func_text.contains("require") {
                // check arguments
                if let Some(args) = node.child_by_field_name("arguments") {
                    let t = args.utf8_text(content.as_bytes()).unwrap_or("");
                    if t.contains("child_process") {
                        let row = node.start_position().row + 1;
                        out.push(Finding {
                            id: format!("ast.js-child-process-{}-{}", path_str, row),
                            severity: Severity::High,
                            confidence: 0.9,
                            rule: "ast.js-child-process".to_string(),
                            category: "ast".to_string(),
                            location: Location {
                                path: path_str.to_string(),
                                line: Some(row),
                                column: Some(node.start_position().column + 1),
                            },
                            message: "AST: require('child_process')".to_string(),
                            snippet: Some(t.chars().take(120).collect()),
                            tags: vec!["ast".to_string(), "javascript".to_string()],
                        });
                    }
                }
            }
        }
    }
    // Recurse.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_js(child, content, path_str, out);
    }
}

fn scan_python(path: &Path, content: &str) -> Vec<Finding> {
    let mut parser = tree_sitter::Parser::new();
    let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(content, None) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let path_str = path.display().to_string();
    walk_py(tree.root_node(), content, &path_str, &mut out);
    out
}

fn walk_py(node: tree_sitter::Node, content: &str, path_str: &str, out: &mut Vec<Finding>) {
    if node.kind() == "call" {
        if let Some(func) = node.child_by_field_name("function") {
            let func_text = func.utf8_text(content.as_bytes()).unwrap_or("");
            let dangerous = matches!(
                func_text,
                "eval" | "exec" | "compile" | "system" | "popen" | "spawn"
            ) || func_text.ends_with(".system")
                || func_text.ends_with(".popen")
                || func_text.ends_with(".call")
                || func_text.ends_with(".run")
                || func_text.ends_with(".Popen")
                || func_text.contains("subprocess");
            if dangerous {
                let row = node.start_position().row + 1;
                out.push(Finding {
                    id: format!("ast.py-dangerous-call-{}-{}", path_str, row),
                    severity: Severity::High,
                    confidence: 0.85,
                    rule: "ast.py-dangerous-call".to_string(),
                    category: "ast".to_string(),
                    location: Location {
                        path: path_str.to_string(),
                        line: Some(row),
                        column: Some(node.start_position().column + 1),
                    },
                    message: format!("AST: dangerous call '{}'", func_text),
                    snippet: node
                        .utf8_text(content.as_bytes())
                        .ok()
                        .map(|s| s.chars().take(120).collect()),
                    tags: vec!["ast".to_string(), "python".to_string()],
                });
            }
            // os.system / subprocess with shell=True handled by text already.
            if func_text.contains("system") || func_text.contains("popen") {
                // already covered
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_py(child, content, path_str, out);
    }
}
