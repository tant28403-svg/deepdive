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
fn scan_secret_dir_is_unsafe() {
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
        .stdout(predicate::str::contains("VERDICT: UNSAFE"));
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
