use crate::types::{Finding, Location, Severity};
use std::collections::BTreeMap;
use std::path::Path;

const JS_SOURCES: &[&str] = &[
    "process.argv",
    "process.env",
    "process.stdin",
    "req.body",
    "req.query",
    "req.params",
    "req.headers",
    "request.body",
    "request.query",
    "request.params",
    "location.search",
    "location.hash",
    "location.href",
    "document.URL",
    "document.referrer",
    "window.name",
    "Deno.args",
    "Bun.argv",
];

const PY_SOURCES: &[&str] = &[
    "sys.argv",
    "sys.stdin",
    "os.environ",
    "os.getenv",
    "request.args",
    "request.form",
    "request.json",
    "flask.request",
    "input(",
];

/// True when `text` contains `name` as a standalone identifier.
fn mentions(text: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(index) = text[from..].find(name) {
        let start = from + index;
        let end = start + name.len();
        let before_ok = start == 0
            || !text.as_bytes()[start - 1].is_ascii_alphanumeric()
                && text.as_bytes()[start - 1] != b'_'
                && text.as_bytes()[start - 1] != b'$';
        let after_ok = end == text.len()
            || !text.as_bytes()[end].is_ascii_alphanumeric()
                && text.as_bytes()[end] != b'_'
                && text.as_bytes()[end] != b'$';
        if before_ok && after_ok {
            return true;
        }
        from = start + name.len();
    }
    false
}

fn tainted_by(value: &str, taint: &BTreeMap<String, String>) -> Option<String> {
    taint
        .iter()
        .find(|(name, _)| mentions(value, name))
        .map(|(_, source)| source.clone())
}

fn source_in(value: &str, sources: &[&str]) -> Option<String> {
    sources
        .iter()
        .find(|source| value.contains(**source))
        .map(|source| (*source).to_string())
}

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
    let mut taint = BTreeMap::new();
    walk_js(tree.root_node(), content, &path_str, &mut out, &mut taint);
    out
}

fn js_sink(func: &str) -> Option<&'static str> {
    if matches!(func, "eval" | "Function") {
        return Some("code injection");
    }
    if func.ends_with(".exec")
        || func == "exec"
        || func.ends_with("execSync")
        || func.ends_with(".spawn")
        || func == "spawn"
        || func.ends_with("spawnSync")
        || func.contains("child_process")
    {
        return Some("command injection");
    }
    if func.ends_with(".runInNewContext")
        || func.ends_with(".runInThisContext")
        || func.ends_with(".runInContext")
        || func == "document.write"
    {
        return Some("code injection");
    }
    if func.ends_with(".query")
        || func.ends_with(".execute")
        || func.ends_with(".raw")
        || func.ends_with(".queryRaw")
    {
        return Some("SQL injection");
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn push_taint(
    out: &mut Vec<Finding>,
    path_str: &str,
    node: tree_sitter::Node,
    content: &str,
    language: &str,
    sink_desc: &str,
    sink: &str,
    source: &str,
) {
    let row = node.start_position().row + 1;
    out.push(Finding {
        id: format!("ast.{}-tainted-sink-{}-{}", language, path_str, row),
        severity: Severity::High,
        confidence: 0.8,
        rule: format!("ast.{}-tainted-sink", language),
        category: "ast".to_string(),
        location: Location {
            path: path_str.to_string(),
            line: Some(row),
            column: Some(node.start_position().column + 1),
        },
        message: format!(
            "AST: user-controlled input '{}' reaches '{}' ({})",
            source, sink, sink_desc
        ),
        snippet: node
            .utf8_text(content.as_bytes())
            .ok()
            .map(|s| s.chars().take(120).collect()),
        tags: vec!["ast".to_string(), language.to_string(), "taint".to_string()],
    });
}

fn simple_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn walk_js(
    node: tree_sitter::Node,
    content: &str,
    path_str: &str,
    out: &mut Vec<Finding>,
    taint: &mut BTreeMap<String, String>,
) {
    // Propagate taint through simple assignments and direct member writes.
    if matches!(node.kind(), "variable_declarator" | "assignment_expression") {
        let name_field = if node.kind() == "variable_declarator" {
            "name"
        } else {
            "left"
        };
        let value_field = if node.kind() == "variable_declarator" {
            "value"
        } else {
            "right"
        };
        if let (Some(name_node), Some(value_node)) = (
            node.child_by_field_name(name_field),
            node.child_by_field_name(value_field),
        ) {
            let name = name_node.utf8_text(content.as_bytes()).unwrap_or("");
            let value = value_node.utf8_text(content.as_bytes()).unwrap_or("");
            let source = tainted_by(value, taint).or_else(|| source_in(value, JS_SOURCES));
            if let Some(source) = source {
                if simple_identifier(name) {
                    taint.insert(name.to_string(), source.clone());
                }
                if name.ends_with(".innerHTML") || name.ends_with(".outerHTML") {
                    push_taint(
                        out,
                        path_str,
                        node,
                        content,
                        "javascript",
                        "cross-site scripting",
                        name,
                        &source,
                    );
                }
            }
        }
    }

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
            if let (Some(sink_desc), Some(args)) =
                (js_sink(func_text), node.child_by_field_name("arguments"))
            {
                let args_text = args.utf8_text(content.as_bytes()).unwrap_or("");
                if let Some(source) =
                    tainted_by(args_text, taint).or_else(|| source_in(args_text, JS_SOURCES))
                {
                    push_taint(
                        out,
                        path_str,
                        node,
                        content,
                        "javascript",
                        sink_desc,
                        func_text,
                        &source,
                    );
                }
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
        walk_js(child, content, path_str, out, taint);
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
    let mut taint = BTreeMap::new();
    walk_py(tree.root_node(), content, &path_str, &mut out, &mut taint);
    out
}

fn py_sink(func: &str) -> Option<&'static str> {
    if matches!(func, "eval" | "exec" | "compile") {
        return Some("code injection");
    }
    if func.ends_with(".system")
        || func.ends_with(".popen")
        || func.ends_with(".execv")
        || func.ends_with(".execvp")
        || func.ends_with(".execve")
        || func == "system"
        || func == "popen"
        || func.contains("subprocess")
    {
        return Some("command injection");
    }
    if func.ends_with("pickle.loads")
        || func.ends_with(".loads")
        || func.ends_with("yaml.load")
        || func.ends_with("marshal.loads")
    {
        return Some("unsafe deserialization");
    }
    if func.ends_with(".execute")
        || func.ends_with(".executemany")
        || func.ends_with(".executescript")
        || func.ends_with(".raw")
    {
        return Some("SQL injection");
    }
    if func.ends_with("render_template_string") {
        return Some("template injection");
    }
    None
}

fn walk_py(
    node: tree_sitter::Node,
    content: &str,
    path_str: &str,
    out: &mut Vec<Finding>,
    taint: &mut BTreeMap<String, String>,
) {
    if matches!(node.kind(), "assignment" | "augmented_assignment") {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let name = left.utf8_text(content.as_bytes()).unwrap_or("");
            let value = right.utf8_text(content.as_bytes()).unwrap_or("");
            if let Some(source) = tainted_by(value, taint).or_else(|| source_in(value, PY_SOURCES))
            {
                if simple_identifier(name) {
                    taint.insert(name.to_string(), source);
                }
            }
        }
    }

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
            if let (Some(sink_desc), Some(args)) =
                (py_sink(func_text), node.child_by_field_name("arguments"))
            {
                let args_text = args.utf8_text(content.as_bytes()).unwrap_or("");
                if let Some(source) =
                    tainted_by(args_text, taint).or_else(|| source_in(args_text, PY_SOURCES))
                {
                    push_taint(
                        out, path_str, node, content, "python", sink_desc, func_text, &source,
                    );
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_py(child, content, path_str, out, taint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn js_tainted_input_reaches_eval() {
        let findings = scan_ast(
            Path::new("app.js"),
            "const cmd = process.argv[2];\neval(cmd);\n",
        );
        assert!(rules(&findings).contains(&"ast.javascript-tainted-sink"));
    }

    #[test]
    fn js_taint_propagates_through_assignments() {
        let findings = scan_ast(
            Path::new("app.js"),
            "const a = req.query.q;\nconst b = a;\nchild_process.exec(b);\n",
        );
        assert!(rules(&findings).contains(&"ast.javascript-tainted-sink"));
    }

    #[test]
    fn js_constant_input_is_not_tainted() {
        let findings = scan_ast(Path::new("app.js"), "const cmd = \"ls\";\neval(cmd);\n");
        assert!(!rules(&findings).contains(&"ast.javascript-tainted-sink"));
    }

    #[test]
    fn js_tainted_inner_html_is_flagged() {
        let findings = scan_ast(
            Path::new("app.js"),
            "const value = location.search;\nel.innerHTML = value;\n",
        );
        assert!(rules(&findings).contains(&"ast.javascript-tainted-sink"));
    }

    #[test]
    fn python_tainted_input_reaches_system() {
        let findings = scan_ast(
            Path::new("app.py"),
            "import sys, os\ncmd = sys.argv[1]\nos.system(cmd)\n",
        );
        assert!(rules(&findings).contains(&"ast.python-tainted-sink"));
    }

    #[test]
    fn python_input_reaches_exec() {
        let findings = scan_ast(Path::new("app.py"), "value = input('> ')\nexec(value)\n");
        assert!(rules(&findings).contains(&"ast.python-tainted-sink"));
    }

    #[test]
    fn python_constant_input_is_not_tainted() {
        let findings = scan_ast(Path::new("app.py"), "value = 'ls'\nos.system(value)\n");
        assert!(!rules(&findings).contains(&"ast.python-tainted-sink"));
    }
}
