use crate::common::get_folder_path;

mod common;

#[test]
fn test_load_computer_info() {
    use arq::computer::ComputerInfo;

    let computer_path = common::get_computer_path();
    let reader =
        std::io::BufReader::new(std::fs::File::open(computer_path.join("computerinfo")).unwrap());
    let ci = ComputerInfo::new(
        reader,
        computer_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
    )
    .unwrap();
    assert_eq!(ci.computer_name, "my-computer-name");
    assert_eq!(ci.user_name, "my-username");
    assert_eq!(ci.uuid, "AA16A39F-AEDC-42A5-A15B-DAA09EA22E1D");
}

#[test]
fn test_loading_encrypted_object_dat() {
    use arq::{folder::Folder, object_encryption::EncryptionDat};
    use std::io::{BufRead, BufReader};

    let ec = common::get_encryptionv3_path();
    let mut reader = BufReader::new(std::fs::File::open(&ec).unwrap());
    let mut buf = Vec::new();
    let _ = reader.read_until(b'-', &mut buf);
    let reader = BufReader::new(std::fs::File::open(ec).unwrap());
    let ec_dat = EncryptionDat::new(reader, common::ENCRYPTION_PASSWORD).unwrap();

    let mut folder = BufReader::new(std::fs::File::open(get_folder_path()).unwrap());
    let _ = Folder::new(&mut folder, &ec_dat.master_keys).unwrap();
}

#[test]
fn test_generate_encryption_v3_dat() {
    use arq::object_encryption::EncryptionDat;
    let _ = EncryptionDat::new(
        std::io::Cursor::new(&EncryptionDat::generate(common::ENCRYPTION_PASSWORD).unwrap()),
        common::ENCRYPTION_PASSWORD,
    )
    .unwrap();
}


// --- Arq 7 Integration Tests ---
#[cfg(test)]
mod arq7_integration_tests {
    use arq::arq7_format::Arq7BackupSet;
    use std::path::Path;

    const ARQ7_UNENCRYPTED_FIXTURE_PATH: &str = "fixtures/arq7_test_backup_unencrypted";
    const ARQ7_ENCRYPTED_FIXTURE_PATH: &str = "fixtures/arq7_test_backup_encrypted";
    const ARQ7_ENCRYPTED_PASSWORD: &str = "testpassword";

    fn run_arq7_integrity_checks(backup_set: &Arq7BackupSet) {
        println!("Backup Config: {:?}", backup_set.config);
        assert_eq!(backup_set.config.backup_name, "Arq7 Test Backup"); // Assuming fixture is named this in Arq UI

        let folder_configs = backup_set.list_backup_folder_configs().unwrap();
        println!("Found {} backup folder configs.", folder_configs.len());
        assert!(!folder_configs.is_empty(), "Should find at least one backup folder config in the fixture");

        for fc_idx in 0..folder_configs.len() {
            let fc = &folder_configs[fc_idx];
            println!("Checking folder config: {} ({})", fc.name, fc.uuid);
            assert!(!fc.uuid.is_empty());
            // Example: Assuming the first folder in the fixture is named "Test Data Source"
            // if fc_idx == 0 {
            //     assert_eq!(fc.name, "Test Data Source");
            // }


            let records = backup_set.list_backup_records(&fc.uuid).unwrap();
            println!("Found {} records for folder {}", records.len(), fc.uuid);

            // Assuming the fixture has at least one backup record for each folder
            assert!(!records.is_empty(), "Should find records for folder {}", fc.uuid);

            for record in records.iter().take(1) { // Check the latest record
                println!("Checking record created at: {} (Version: {})", record.creation_date, record.arq_version);
                assert!(record.is_complete, "Record should be complete");
                assert!(record.node.is_some(), "Record should have a root node");

                // TODO: When binary Node/Tree parsing is available, extend this to:
                // 1. Get the root Node/Tree blob using record.node.tree_blob_loc.
                // 2. Parse the root Tree.
                // 3. List root directory contents.
                // 4. Attempt to "read" a known file (fetch its data blobs).
                //    - For now, just checking if data_blob_locs exist if it's a file node.
                if let Some(node_json) = &record.node {
                    if !node_json.is_tree { // If the root node itself is a file (unlikely for a folder backup)
                        assert!(!node_json.data_blob_locs.is_empty(), "File node should have data blobs");
                    } else {
                        assert!(node_json.tree_blob_loc.is_some(), "Tree node should have a tree blob location");
                    }
                }
            }
        }
    }

    #[test]
    #[ignore] // Ignored by default as it requires a specific fixture setup
    fn test_read_unencrypted_arq7_backup() {
        let fixture_path = Path::new(ARQ7_UNENCRYPTED_FIXTURE_PATH);
        if !fixture_path.exists() {
            println!("Skipping test_read_unencrypted_arq7_backup: fixture not found at {}", ARQ7_UNENCRYPTED_FIXTURE_PATH);
            return;
        }

        let backup_set = Arq7BackupSet::load(fixture_path, None).expect("Failed to load unencrypted backup set");
        assert!(!backup_set.config.is_encrypted, "Backup set should be unencrypted");
        run_arq7_integrity_checks(&backup_set);
    }

    #[test]
    #[ignore] // Ignored by default as it requires a specific fixture setup
    fn test_read_encrypted_arq7_backup() {
        let fixture_path = Path::new(ARQ7_ENCRYPTED_FIXTURE_PATH);
        if !fixture_path.exists() {
            println!("Skipping test_read_encrypted_arq7_backup: fixture not found at {}", ARQ7_ENCRYPTED_FIXTURE_PATH);
            return;
        }

        let backup_set = Arq7BackupSet::load(fixture_path, Some(ARQ7_ENCRYPTED_PASSWORD))
            .expect("Failed to load encrypted backup set with correct password");

        assert!(backup_set.config.is_encrypted, "Backup set should be encrypted");
        assert!(backup_set.keys.is_some(), "Keys should be loaded for encrypted backup");
        run_arq7_integrity_checks(&backup_set);
    }

    #[test]
    #[ignore] // Ignored by default
    fn test_read_encrypted_arq7_backup_wrong_password() {
        let fixture_path = Path::new(ARQ7_ENCRYPTED_FIXTURE_PATH);
        if !fixture_path.exists() {
            println!("Skipping test_read_encrypted_arq7_backup_wrong_password: fixture not found at {}", ARQ7_ENCRYPTED_FIXTURE_PATH);
            return;
        }

        let result = Arq7BackupSet::load(fixture_path, Some("wrongpassword"));
        assert!(result.is_err(), "Loading encrypted backup with wrong password should fail");
        // TODO: Check for specific error type Error::WrongPassword or similar from EncryptedKeySet::decrypt
        // if let Err(e) = result {
        //     assert!(matches!(e, arq::error::Error::WrongPassword));
        // }
    }
}
