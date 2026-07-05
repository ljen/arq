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
        .env("ARQ_PASSWORD", ARQ5_PASSWORD)
        .arg("folders");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Folders for computer AA16A39F-AEDC-42A5-A15B-DAA09EA22E1D",
        ))
        .stdout(predicate::str::contains("Bucket: arq 5"))
        .stdout(predicate::str::contains(
            "7C19E8AF-FFE9-4952-B1E1-8D5181012BB1",
        ));
}

#[test]
#[ignore = "Missing fixture bucketdata directory"]
fn test_arq5_show_tree() {
    let mut cmd = get_evu_cmd();
    cmd.arg("show")
        .arg("--path")
        .arg(format!("{}/{}", ARQ5_FIXTURE_PATH, ARQ5_COMPUTER_UUID))
        .env("ARQ_PASSWORD", ARQ5_PASSWORD)
        .arg("tree")
        .arg("--folder")
        .arg("7C19E8AF-FFE9-4952-B1E1-8D5181012BB1");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Tree for folder 7C19E8AF-FFE9-4952-B1E1-8D5181012BB1",
        ))
        .stdout(predicate::str::contains("my-file.txt"));
}
