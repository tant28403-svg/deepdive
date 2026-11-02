use crate::analysis::file_type::FileType;
use crate::analysis::sigma::{self as sigma_engine, SigmaRule};
use crate::analysis::yara::YaraRules;
use crate::analysis::{deps, file_type, git_history, rules as rule_engine, scan, symlinks, walker};
use crate::config::{self, ProjectConfig};
use crate::risk;
use crate::types::{Finding, Severity, Verdict};
use anyhow::Result;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Options {
    pub format: String,
    pub out: Option<PathBuf>,
    pub min_severity: String,
    pub offline: bool,
    pub deep: bool,
    pub sandbox: bool,
    pub sandbox_cmd: Option<String>,
    pub sandbox_backend: String,
    pub sandbox_policy: String,
    pub intel: bool,
    pub baseline: Option<PathBuf>,
    pub regression: bool,
    pub max_size: u64,
    pub threads: Option<usize>,
    pub rules: Vec<PathBuf>,
    pub fail_on: Option<String>,
    pub no_color: bool,
    pub sbom: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            format: "text".to_string(),
            out: None,
            min_severity: "info".to_string(),
            offline: false,
            deep: false,
            sandbox: false,
            sandbox_cmd: None,
            sandbox_backend: "auto".to_string(),
            sandbox_policy: "strict".to_string(),
            intel: false,
            baseline: None,
            regression: false,
            max_size: 100,
            threads: None,
            rules: Vec::new(),
            fail_on: None,
            no_color: false,
            sbom: None,
        }
    }
}

/// Run the full static (and optional dynamic) pipeline on a local path.
/// Returns the process exit code: 0 safe, 1 review, 2 unsafe.
pub fn execute(path: &Path, opts: &Options) -> Result<i32> {
    if !path.exists() {
        anyhow::bail!("target not found: {}", path.display());
    }

    // Merge global config defaults without overriding explicit CLI flags.
    let mut offline = opts.offline;
    let mut min_severity = opts.min_severity.clone();
    let mut rule_paths = opts.rules.clone();
    if let Ok(global) = config::Config::load() {
        if Severity::parse(&min_severity) == Some(Severity::Info) {
            if let Some(value) = global.min_severity {
                min_severity = value;
            }
        }
        if !offline && global.offline == Some(true) {
            offline = true;
        }
        for rule in global.rules {
            rule_paths.push(PathBuf::from(rule));
        }
    }

    if let Some(threads) = opts.threads {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global();
    }

    let files = walker::walk_files(path, opts.max_size);
    let types: Vec<FileType> = files.par_iter().map(|f| file_type::detect(f)).collect();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for ft in &types {
        *counts.entry(ft.as_str()).or_insert(0) += 1;
    }

    // File scanning (parallel).
    let mut findings: Vec<Finding> = files
        .par_iter()
        .map(|file| scan::read_and_scan(file))
        .collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .collect();

    // Filesystem-level checks run once per root.
    if path.is_dir() {
        findings.extend(symlinks::scan_root(path));
        findings.extend(crate::analysis::windows_extras::scan_tree(path));
    }

    // Dependency audit + typosquatting.
    let dependencies = deps::collect_dependencies(&files);
    if !dependencies.is_empty() {
        findings.extend(deps::audit_dependencies(&dependencies, offline));
    }
    // Lockfile integrity, dependency confusion, and manifest drift.
    findings.extend(deps::scan_integrity(&files));

    // Custom detection rules (user dir + --rules): TOML, Sigma, and YARA.
    let custom_rules = load_all_rules(&rule_paths);
    if !custom_rules.toml.is_empty() {
        let rule_findings: Vec<Finding> = files
            .par_iter()
            .zip(types.par_iter())
            .filter(|(_, ft)| is_text_type(ft))
            .map(|(file, _)| {
                let content = scan::read_text(file);
                rule_engine::scan_with_rules(file, &content, &custom_rules.toml)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();
        findings.extend(rule_findings);
    }
    if !custom_rules.sigma.is_empty() {
        let rule_findings: Vec<Finding> = files
            .par_iter()
            .zip(types.par_iter())
            .filter(|(_, ft)| is_text_type(ft))
            .map(|(file, _)| {
                let content = scan::read_text(file);
                sigma_engine::scan(file, &content, &custom_rules.sigma)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();
        findings.extend(rule_findings);
    }
    if !custom_rules.yara.is_empty() {
        let rule_findings: Vec<Finding> = files
            .par_iter()
            .filter_map(|file| {
                std::fs::read(file)
                    .ok()
                    .map(|bytes| custom_rules.yara.scan(file, &bytes))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();
        findings.extend(rule_findings);
    }

    // Cached threat-intel URL/host matching.
    if opts.intel {
        let db = crate::analysis::intel::IntelDb::load();
        if db.is_empty() {
            eprintln!("[intel] no cached feed; run `deepdive cache update` while online");
        } else {
            let intel_findings: Vec<Finding> = files
                .par_iter()
                .zip(types.par_iter())
                .filter(|(_, ft)| is_text_type(ft))
                .flat_map(|(file, _)| {
                    let content = scan::read_text(file);
                    crate::analysis::intel::scan_text(file, &content, &db)
                })
                .collect();
            findings.extend(intel_findings);
        }
    }

    // Git history (deep mode).
    if opts.deep && path.is_dir() {
        findings.extend(git_history::scan_git_history(path));
    }

    // Opt-in sandbox execution.
    let mut sandbox_report: Option<crate::types::SandboxReport> = None;
    if opts.sandbox || opts.sandbox_cmd.is_some() {
        if !path.is_dir() {
            eprintln!("[sandbox] skipped: sandbox requires a directory target, not a file");
        } else {
            let command = opts.sandbox_cmd.clone().unwrap_or_else(|| {
                // Platform-appropriate no-op command
                if cfg!(windows) {
                    "cmd /c exit 0".to_string()
                } else {
                    "true".to_string()
                }
            });
            match build_sandbox_policy(opts).and_then(|policy| {
                crate::sandbox::run(&policy, &command, path)
                    .map_err(|err| anyhow::anyhow!("{}", err))
            }) {
                Ok(report) => {
                    findings.extend(crate::sandbox::behavioral_findings(&report));
                    sandbox_report = Some(report);
                }
                Err(err) => eprintln!("[sandbox] failed: {}", err),
            }
        }
    }

    // Project allowlist / rule toggles / severity overrides.
    let project = ProjectConfig::load(path);
    let suppressed = project.apply(&mut findings);

    // Baseline comparison against a previous JSON report.
    let baseline_diff = match &opts.baseline {
        Some(baseline_path) => {
            let previous = crate::analysis::baseline::load(baseline_path)?;
            Some(crate::analysis::baseline::compare(&findings, &previous))
        }
        None => None,
    };
    if let Some(diff) = &baseline_diff {
        if !diff.new.is_empty() {
            findings.push(Finding {
                id: "baseline.new-findings".to_string(),
                severity: Severity::Info,
                confidence: 1.0,
                rule: "baseline.new-findings".to_string(),
                category: "baseline".to_string(),
                location: crate::types::Location {
                    path: path.to_string_lossy().to_string(),
                    line: None,
                    column: None,
                },
                message: format!(
                    "{} new finding(s) compared with the baseline",
                    diff.new.len()
                ),
                snippet: None,
                tags: vec!["baseline".to_string()],
            });
        }
    }

    let regression_fail = opts.regression
        && baseline_diff
            .as_ref()
            .and_then(|diff| diff.highest_new_severity())
            .map(|severity| severity >= Severity::High)
            .unwrap_or(false);

    let score = risk::score(&findings);
    let verdict = risk::verdict(score, &findings);
    let mut exit = exit_code(opts, verdict, &findings);
    if regression_fail {
        exit = 2;
    }

    // --min-severity filters presentation only; it never lowers the verdict.
    let min = Severity::parse(&min_severity);
    let mut reported: Vec<Finding> = match min {
        Some(threshold) => findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .cloned()
            .collect(),
        None => findings.clone(),
    };
    reported.sort_by_key(|a| std::cmp::Reverse(a.severity));

    let color = !opts.no_color && std::io::stdout().is_terminal();
    if let Some(sbom_format) = &opts.sbom {
        let content = match sbom_format.to_lowercase().as_str() {
            "spdx" => crate::reporting::sbom::spdx(&dependencies, path),
            _ => crate::reporting::sbom::cyclonedx(&dependencies, path),
        };
        write_output(&opts.out, &content)?;
        return Ok(exit);
    }
    match opts.format.to_lowercase().as_str() {
        "json" => {
            let content = serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": crate::types::SCHEMA_VERSION,
                "files_scanned": files.len(),
                "risk_score": score,
                "verdict": verdict.as_str(),
                "suppressed": suppressed,
                "findings": reported,
                "sandbox": sandbox_report,
                "baseline": baseline_diff.as_ref().map(|diff| serde_json::json!({
                    "new": diff.new.len(),
                    "resolved": diff.resolved.len(),
                    "new_findings": diff.new,
                })),
            }))?;
            write_output(&opts.out, &content)?;
        }
        "sarif" => {
            let content =
                crate::reporting::sarif::render(&reported, files.len(), env!("CARGO_PKG_VERSION"));
            write_output(&opts.out, &content)?;
        }
        _ => {
            println!("deepdive scan: {}", path.display());
            println!("files scanned: {}", files.len());
            for (name, count) in &counts {
                println!("  {:<16} {}", name, count);
            }
            println!();
            println!(
                "VERDICT: {}  (risk score {}/100)",
                verdict_word(&verdict, color),
                score
            );
            println!();
            for f in &reported {
                println!(
                    "[{}] {} - {}",
                    severity_label(f.severity, color),
                    f.rule,
                    f.location.path
                );
                if let Some(line) = f.location.line {
                    println!("  line {}: {}", line, f.message);
                } else {
                    println!("  {}", f.message);
                }
                if let Some(snippet) = &f.snippet {
                    println!("  > {}", snippet);
                }
            }
            println!();
            let mut summary: BTreeMap<Severity, usize> = BTreeMap::new();
            for f in &reported {
                *summary.entry(f.severity).or_insert(0) += 1;
            }
            println!(
                "Summary: critical={}, high={}, medium={}, low={}, info={}",
                summary.get(&Severity::Critical).unwrap_or(&0),
                summary.get(&Severity::High).unwrap_or(&0),
                summary.get(&Severity::Medium).unwrap_or(&0),
                summary.get(&Severity::Low).unwrap_or(&0),
                summary.get(&Severity::Info).unwrap_or(&0),
            );
            if suppressed > 0 {
                println!("Suppressed by .deepdive.toml: {}", suppressed);
            }
            if let Some(diff) = &baseline_diff {
                println!();
                println!(
                    "baseline: {} new, {} resolved",
                    diff.new.len(),
                    diff.resolved.len()
                );
                for finding in diff.new.iter().take(20) {
                    println!(
                        "  NEW [{}] {} - {}",
                        finding.severity.as_str().to_uppercase(),
                        finding.rule,
                        finding.location.path
                    );
                }
            }
            if let Some(report) = &sandbox_report {
                print_sandbox_report(report);
            }
        }
    }

    Ok(exit)
}

fn exit_code(opts: &Options, verdict: Verdict, findings: &[Finding]) -> i32 {
    if let Some(threshold) = &opts.fail_on {
        let threshold = Severity::parse(threshold).unwrap_or(Severity::Info);
        if findings.iter().any(|f| f.severity >= threshold) {
            return 2;
        }
        return 0;
    }
    match verdict {
        Verdict::Safe => 0,
        Verdict::Review => 1,
        Verdict::Unsafe | Verdict::Block => 2,
    }
}

fn build_sandbox_policy(opts: &Options) -> Result<crate::sandbox::policy::SandboxPolicy> {
    use crate::sandbox::policy::{Backend, SandboxPolicy};

    let backend = Backend::parse(&opts.sandbox_backend)
        .ok_or_else(|| anyhow::anyhow!("unknown sandbox backend '{}'", opts.sandbox_backend))?;
    Ok(SandboxPolicy::from_spec(&opts.sandbox_policy)?.with_backend(backend))
}

fn print_sandbox_report(report: &crate::types::SandboxReport) {
    println!();
    println!("[sandbox] backend: {}", report.backend);
    println!(
        "[sandbox] policy: network={}",
        report.policy.network_label()
    );
    println!("[sandbox] exit code: {:?}", report.exit_code);
    println!("[sandbox] duration: {} ms", report.duration_ms);
    println!("[sandbox] timed out: {}", report.timed_out);
    println!("[sandbox] files created: {}", report.files_created.len());
    println!("[sandbox] files modified: {}", report.files_modified.len());
    println!("[sandbox] files deleted: {}", report.files_deleted.len());
    println!(
        "[sandbox] network indicators: {}",
        report.network_indicators.len()
    );
    if !report.process_tree.is_empty() {
        println!("[sandbox] processes: {}", report.process_tree.len());
    }
    if !report.syscalls.is_empty() {
        println!("[sandbox] syscalls: {}", report.syscalls.len());
    }
    if !report.network_events.is_empty() {
        println!("[sandbox] network events: {}", report.network_events.len());
    }
    if !report.registry_changes.is_empty() {
        println!(
            "[sandbox] registry changes: {}",
            report.registry_changes.len()
        );
    }
    if !report.memory_dumps.is_empty() {
        println!("[sandbox] memory dumps: {}", report.memory_dumps.len());
    }
    if !report.stdout.is_empty() {
        println!("[sandbox stdout]\n{}", report.stdout);
    }
    if !report.stderr.is_empty() {
        println!("[sandbox stderr]\n{}", report.stderr);
    }
}

fn write_output(out: &Option<PathBuf>, content: &str) -> Result<()> {
    match out {
        Some(path) => {
            std::fs::write(path, content)?;
            println!("wrote {}", path.display());
        }
        None => println!("{}", content),
    }
    Ok(())
}

fn is_text_type(ft: &FileType) -> bool {
    matches!(
        ft,
        FileType::Source | FileType::Script | FileType::Text | FileType::Config | FileType::Unknown
    )
}

struct RuleBundle {
    toml: Vec<rule_engine::Rule>,
    sigma: Vec<SigmaRule>,
    yara: YaraRules,
}

fn load_all_rules(extra: &[PathBuf]) -> RuleBundle {
    use std::collections::BTreeSet;

    let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
    if let Some(dir) = config::rules_dir() {
        collect_rule_paths(&dir, &mut paths);
    }
    for path in extra {
        if path.is_dir() {
            collect_rule_paths(path, &mut paths);
        } else {
            paths.insert(path.clone());
        }
    }

    let mut bundle = RuleBundle {
        toml: Vec::new(),
        sigma: Vec::new(),
        yara: YaraRules::empty(),
    };
    let mut yara_paths = Vec::new();
    for path in paths {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        match extension.as_str() {
            "toml" => bundle.toml.extend(rule_engine::load_rules_file(&path)),
            "yml" | "yaml" => match sigma_engine::load_file(&path) {
                Ok(rules) => bundle.sigma.extend(rules),
                Err(err) => eprintln!("warning: {}", err),
            },
            "yar" | "yara" => yara_paths.push(path),
            _ => {}
        }
    }
    match YaraRules::compile(&yara_paths) {
        Ok(rules) => bundle.yara = rules,
        Err(err) => eprintln!(
            "warning: YARA rules disabled after a compile error: {}",
            err
        ),
    }
    bundle
}

fn collect_rule_paths(dir: &Path, out: &mut std::collections::BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            out.insert(path);
        }
    }
}

fn severity_label(severity: Severity, color: bool) -> String {
    let label = severity.as_str().to_uppercase();
    if !color {
        return label;
    }
    use owo_colors::OwoColorize;
    match severity {
        Severity::Critical => label.red().bold().to_string(),
        Severity::High => label.bright_red().to_string(),
        Severity::Medium => label.yellow().to_string(),
        Severity::Low => label.blue().to_string(),
        Severity::Info => label.dimmed().to_string(),
    }
}

fn verdict_word(verdict: &Verdict, color: bool) -> String {
    let word = verdict.as_str();
    if !color {
        return word.to_string();
    }
    use owo_colors::OwoColorize;
    match verdict {
        Verdict::Safe => word.green().bold().to_string(),
        Verdict::Review => word.yellow().bold().to_string(),
        Verdict::Unsafe | Verdict::Block => word.red().bold().to_string(),
    }
}
