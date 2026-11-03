use crate::types::{Finding, Location, Severity};
use std::path::Path;

pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let path_str = path.display().to_string();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Jupyter notebooks
    if name.ends_with(".ipynb") {
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                if let Some(cells) = v.get("cells").and_then(|c| c.as_array()) {
                    for (i, cell) in cells.iter().enumerate() {
                        if cell.get("cell_type").and_then(|t| t.as_str()) == Some("code") {
                            let src = cell.get("source");
                            let code = match src {
                                Some(serde_json::Value::Array(a)) => a
                                    .iter()
                                    .filter_map(|x| x.as_str())
                                    .collect::<Vec<_>>()
                                    .join(""),
                                Some(serde_json::Value::String(s)) => s.clone(),
                                _ => String::new(),
                            };
                            // Run source detectors on code cell.
                            let tmp = path.to_path_buf();
                            out.extend(crate::analysis::source::scan(&tmp, &code));
                            out.extend(crate::analysis::obfuscation::scan(&tmp, &code));
                            // Flag shell escapes.
                            if code.contains("!")
                                && (code.contains("pip ")
                                    || code.contains("apt ")
                                    || code.contains("wget")
                                    || code.contains("curl"))
                            {
                                out.push(Finding {
                                    id: format!("doc.notebook-shell-{}-{}", path_str, i),
                                    severity: Severity::Medium,
                                    confidence: 0.7,
                                    rule: "doc.notebook-shell-escape".to_string(),
                                    category: "document".to_string(),
                                    location: Location {
                                        path: path_str.clone(),
                                        line: Some(i + 1),
                                        column: None,
                                    },
                                    message: "Notebook code cell invokes shell/magic command"
                                        .to_string(),
                                    snippet: Some(code.chars().take(120).collect()),
                                    tags: vec!["jupyter".to_string()],
                                });
                            }
                        }
                    }
                }
            }
        }
        return out;
    }

    // PDF
    if name.ends_with(".pdf") {
        let text = String::from_utf8_lossy(bytes);
        let checks = [
            ("/JavaScript", "JavaScript in PDF", Severity::High),
            ("/JS ", "JavaScript in PDF", Severity::High),
            ("/OpenAction", "Auto-open action in PDF", Severity::High),
            ("/Launch", "Launch action in PDF", Severity::Critical),
            ("/EmbeddedFile", "Embedded file in PDF", Severity::Medium),
            ("/RichMedia", "Rich media in PDF", Severity::Medium),
        ];
        for (pat, msg, sev) in checks {
            if text.contains(pat) {
                out.push(Finding {
                    id: format!("doc.pdf-{}-{}", path_str, pat),
                    severity: sev,
                    confidence: 0.8,
                    rule: "doc.pdf-active-content".to_string(),
                    category: "document".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: msg.to_string(),
                    snippet: None,
                    tags: vec!["pdf".to_string()],
                });
            }
        }
        return out;
    }

    // Legacy Office (OLE compound files): macro/DDE indicators.
    if name.ends_with(".doc") || name.ends_with(".xls") || name.ends_with(".ppt") {
        let is_ole =
            bytes.len() >= 8 && bytes[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        if is_ole {
            let strings = crate::analysis::windows_extras::all_strings(bytes);
            let joined = strings.join("\n").to_lowercase();
            let macro_markers = [
                "vbaproject",
                "vba",
                "autoopen",
                "auto_open",
                "autoexec",
                "document_open",
                "workbook_open",
            ];
            if macro_markers.iter().any(|m| joined.contains(m)) {
                out.push(Finding {
                    id: format!("doc.office-vba-macro-{}", path_str),
                    severity: Severity::High,
                    confidence: 0.75,
                    rule: "doc.office-vba-macro".to_string(),
                    category: "document".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: "Legacy Office document contains VBA macro artifacts".to_string(),
                    snippet: None,
                    tags: vec!["office".to_string(), "ole".to_string()],
                });
            }
            if joined.contains("ddeauto") || joined.contains("dde ") {
                out.push(Finding {
                    id: format!("doc.office-dde-{}", path_str),
                    severity: Severity::Critical,
                    confidence: 0.8,
                    rule: "doc.office-dde".to_string(),
                    category: "document".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: "Legacy Office document uses DDE (command execution)".to_string(),
                    snippet: None,
                    tags: vec!["office".to_string(), "dde".to_string()],
                });
            }
            if (joined.contains("http://") || joined.contains("https://"))
                && (joined.contains("template") || joined.contains("attach"))
            {
                out.push(Finding {
                    id: format!("doc.office-remote-template-{}", path_str),
                    severity: Severity::Medium,
                    confidence: 0.65,
                    rule: "doc.office-remote-template".to_string(),
                    category: "document".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: "Legacy Office document references a remote template/attachment"
                        .to_string(),
                    snippet: None,
                    tags: vec!["office".to_string(), "ole".to_string()],
                });
            }
        }
        return out;
    }

    // Office (zip-based)
    if name.ends_with(".docx")
        || name.ends_with(".xlsx")
        || name.ends_with(".pptx")
        || name.ends_with(".odt")
        || name.ends_with(".ods")
    {
        if let Ok(mut zip) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
            // Check for VBA macros.
            let has_vba = (0..zip.len()).any(|i| {
                if let Ok(e) = zip.by_index(i) {
                    if let Ok(name) = e.name() {
                        return name.to_lowercase().contains("vbaproject.bin");
                    }
                }
                false
            });
            if has_vba {
                out.push(Finding {
                    id: format!("doc.office-macro-{}", path_str),
                    severity: Severity::High,
                    confidence: 0.9,
                    rule: "doc.office-vba-macro".to_string(),
                    category: "document".to_string(),
                    location: Location {
                        path: path_str.clone(),
                        line: None,
                        column: None,
                    },
                    message: "Office document contains VBA macros".to_string(),
                    snippet: None,
                    tags: vec!["office".to_string()],
                });
            }
            // External links / template injection.
            for i in 0..zip.len() {
                if let Ok(e) = zip.by_index(i) {
                    let Ok(name) = e.name() else { continue };
                    let n = name.to_lowercase();
                    if n.contains("externallink") || n.contains("attachedtemplate") {
                        out.push(Finding {
                            id: format!("doc.office-external-{}-{}", path_str, i),
                            severity: Severity::Medium,
                            confidence: 0.7,
                            rule: "doc.office-external-link".to_string(),
                            category: "document".to_string(),
                            location: Location {
                                path: path_str.clone(),
                                line: None,
                                column: None,
                            },
                            message: "Office document references external link/template"
                                .to_string(),
                            snippet: Some(name.to_string()),
                            tags: vec!["office".to_string()],
                        });
                    }
                }
            }
        }
        return out;
    }

    // HTML / SVG
    if name.ends_with(".html") || name.ends_with(".htm") || name.ends_with(".svg") {
        let text = String::from_utf8_lossy(bytes);
        let lower = text.to_lowercase();
        if lower.contains("<script") {
            out.push(Finding {
                id: format!("doc.html-script-{}", path_str),
                severity: Severity::Medium,
                confidence: 0.6,
                rule: "doc.html-inline-script".to_string(),
                category: "document".to_string(),
                location: Location {
                    path: path_str.clone(),
                    line: None,
                    column: None,
                },
                message: "HTML/SVG contains inline script".to_string(),
                snippet: None,
                tags: vec![],
            });
        }
        if lower.contains("eval(") || lower.contains("document.write") {
            out.push(Finding {
                id: format!("doc.html-eval-{}", path_str),
                severity: Severity::High,
                confidence: 0.7,
                rule: "doc.html-eval".to_string(),
                category: "document".to_string(),
                location: Location {
                    path: path_str.clone(),
                    line: None,
                    column: None,
                },
                message: "HTML/SVG uses eval/document.write".to_string(),
                snippet: None,
                tags: vec![],
            });
        }
    }

    out
}
