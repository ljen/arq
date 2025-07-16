use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

const ARQ5_COMPUTER_UUID: &str = "AA16A39F-AEDC-42A5-A15B-DAA09EA22E1D";
const ARQ5_FIXTURE_PATH: &str = "../arq/fixtures";
const ARQ5_PASSWORD: &str = "evu";

fn get_evu_cmd() -> Command {
    Command::cargo_bin("evu").unwrap()
}

#[test]
fn test_arq5_show_folders() {
    let mut cmd = get_evu_cmd();
    cmd.arg("show")
        .arg("--path")
        .arg(format!("{}/{}", ARQ5_FIXTURE_PATH, ARQ5_COMPUTER_UUID))
        .arg("--password")
        .arg(ARQ5_PASSWORD)
        .arg("folders");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Folders for computer AA16A39F-AEDC-42A5-A15B-DAA09EA22E1D"))
        .stdout(predicate::str::contains("Bucket: company"))
        .stdout(predicate::str::contains("408E376B-ECF7-4688-902A-1E7671BC5B9A"));
}

#[test]
fn test_arq5_show_tree() {
    let mut cmd = get_evu_cmd();
    cmd.arg("show")
        .arg("--path")
        .arg(format!("{}/{}", ARQ5_FIXTURE_PATH, ARQ5_COMPUTER_UUID))
        .arg("--password")
        .arg(ARQ5_PASSWORD)
        .arg("tree")
        .arg("--folder")
        .arg("408E376B-ECF7-4688-902A-1E7671BC5B9A");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Tree for folder 408E376B-ECF7-4688-902A-1E7671BC5B9A"))
        .stdout(predicate::str::contains("my-file.txt"));
}
