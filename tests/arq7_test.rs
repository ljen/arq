// tests/arq7_test.rs

use arq::arq7_format::{BackupConfig, BlobIdentifierType, BackupFolders, BackupFolder};
use arq::error::Result;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_parse_backup_config_minimal() -> Result<()> {
    let json_content = r#"
    {
        "blobIdentifierType": 2,
        "maxPackedItemLength": 256000,
        "backupName": "Test Backup",
        "isWORM": false,
        "containsGlacierArchives": false,
        "additionalUnpackedBlobDirs": [],
        "chunkerVersion": 3,
        "computerName": "TestComputer",
        "computerSerial": "unused",
        "blobStorageClass": "STANDARD",
        "isEncrypted": false
    }
    "#;

    let dir = tempdir()?;
    let file_path = dir.path().join("backupconfig.json");
    let mut temp_file = File::create(&file_path)?;
    writeln!(temp_file, "{}", json_content)?;

    let config = BackupConfig::from_path(&file_path)?;

    assert_eq!(config.blob_identifier_type, BlobIdentifierType::Sha256);
    assert_eq!(config.max_packed_item_length, 256000);
    assert_eq!(config.backup_name, "Test Backup");
    assert!(!config.is_worm);
    assert!(!config.contains_glacier_archives);
    assert!(config.additional_unpacked_blob_dirs.is_empty());
    assert_eq!(config.chunker_version, 3);
    assert_eq!(config.computer_name, "TestComputer");
    assert_eq!(config.computer_serial, "unused");
    assert_eq!(config.blob_storage_class, "STANDARD");
    assert!(!config.is_encrypted);

    dir.close()?;
    Ok(())
}

#[test]
fn test_parse_backup_config_encrypted() -> Result<()> {
    let json_content = r#"
    {
        "blobIdentifierType": 1,
        "maxPackedItemLength": 512000,
        "backupName": "Encrypted Backup",
        "isWORM": false,
        "containsGlacierArchives": true,
        "additionalUnpackedBlobDirs": ["objects", "objects2"],
        "chunkerVersion": 3,
        "computerName": "MyMac",
        "computerSerial": "SERIAL123",
        "blobStorageClass": "DEEP_ARCHIVE",
        "isEncrypted": true
    }
    "#;

    let dir = tempdir()?;
    let file_path = dir.path().join("backupconfig.json");
    let mut temp_file = File::create(&file_path)?;
    writeln!(temp_file, "{}", json_content)?;

    let config = BackupConfig::from_path(&file_path)?;

    assert_eq!(config.blob_identifier_type, BlobIdentifierType::Sha1);
    assert_eq!(config.max_packed_item_length, 512000);
    assert_eq!(config.backup_name, "Encrypted Backup");
    assert!(config.contains_glacier_archives);
    assert_eq!(config.additional_unpacked_blob_dirs, vec!["objects".to_string(), "objects2".to_string()]);
    assert!(config.is_encrypted);
    assert_eq!(config.blob_storage_class, "DEEP_ARCHIVE");


    dir.close()?;
    Ok(())
}

#[test]
fn test_parse_backup_folders_minimal() -> Result<()> {
    let json_content = r#"
    {
        "standardObjectDirs": ["/some/path/standardobjects"]
    }
    "#;
    let dir = tempdir()?;
    let file_path = dir.path().join("backupfolders.json");
    let mut temp_file = File::create(&file_path)?;
    writeln!(temp_file, "{}", json_content)?;

    let bf = BackupFolders::from_path(&file_path)?;
    assert_eq!(bf.standard_object_dirs, vec!["/some/path/standardobjects".to_string()]);
    assert!(bf.standard_ia_object_dirs.is_empty()); // Check default empty
    assert!(bf.s3_glacier_object_dirs.is_empty());
    assert!(bf.imported_from.is_none());

    dir.close()?;
    Ok(())
}

#[test]
fn test_parse_backup_folders_all_fields() -> Result<()> {
    let json_content = r#"
    {
        "standardObjectDirs": ["/path1/standardobjects"],
        "standardIAObjectDirs": ["/path1/standardiaobjects"],
        "onezoneIAObjectDirs": ["/path1/onezoneiaobjects"],
        "s3GlacierObjectDirs": ["/path1/s3glacierobjects"],
        "s3DeepArchiveObjectDirs": ["/path1/s3deeparchiveobjects"],
        "importedFrom": "5.x"
    }
    "#;
    let dir = tempdir()?;
    let file_path = dir.path().join("backupfolders.json");
    let mut temp_file = File::create(&file_path)?;
    writeln!(temp_file, "{}", json_content)?;

    let bf = BackupFolders::from_path(&file_path)?;
    assert_eq!(bf.standard_object_dirs, vec!["/path1/standardobjects".to_string()]);
    assert_eq!(bf.standard_ia_object_dirs, vec!["/path1/standardiaobjects".to_string()]);
    assert_eq!(bf.onezone_ia_object_dirs, vec!["/path1/onezoneiaobjects".to_string()]);
    assert_eq!(bf.s3_glacier_object_dirs, vec!["/path1/s3glacierobjects".to_string()]);
    assert_eq!(bf.s3_deep_archive_object_dirs, vec!["/path1/s3deeparchiveobjects".to_string()]);
    assert_eq!(bf.imported_from, Some("5.x".to_string()));

    dir.close()?;
    Ok(())
}


#[test]
fn test_parse_backup_folder_config() -> Result<()> {
    let json_content = r#"
    {
        "localPath": "/Users/stefan",
        "migratedFromArq60": false,
        "storageClass": "STANDARD",
        "diskIdentifier": "ROOT_DISK_UUID",
        "uuid": "F1F83A27-E4EA-4994-BD9C-F63A682EBB80",
        "migratedFromArq5": true,
        "localMountPoint": "/",
        "name": "My Documents"
    }
    "#;
    let dir = tempdir()?;
    let file_path = dir.path().join("backupfolder.json");
    let mut temp_file = File::create(&file_path)?;
    writeln!(temp_file, "{}", json_content)?;

    letbfc = BackupFolder::from_path(&file_path)?;
    assert_eq!(bfc.local_path, "/Users/stefan");
    assert!(!bfc.migrated_from_arq60);
    assert_eq!(bfc.storage_class, "STANDARD");
    assert_eq!(bfc.disk_identifier, "ROOT_DISK_UUID");
    assert_eq!(bfc.uuid, "F1F83A27-E4EA-4994-BD9C-F63A682EBB80");
    assert!(bfc.migrated_from_arq5);
    assert_eq!(bfc.local_mount_point, "/");
    assert_eq!(bfc.name, "My Documents");

    dir.close()?;
    Ok(())
}

use arq::arq7_format::EncryptedKeySet;
use std::io::Cursor;

// Placeholder for EncryptedKeySet tests
// Actual test data (valid salt, hmac, iv, ciphertext for a known password and plaintext) is needed.
// This is hard to generate without a reference implementation or Arq itself.
mod encrypted_keyset_tests {
    use super::*;
    // Helper to create a dummy EncryptedKeySet file structure for parsing tests
    // This doesn't create valid crypto data, just structure.
    fn create_dummy_keyset_bytes(salt: &[u8; 8], hmac: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ARQ_ENCRYPTED_MASTER_KEYS"); // 25 bytes header
        bytes.extend_from_slice(salt);
        bytes.extend_from_slice(hmac);
        bytes.extend_from_slice(iv);
        bytes.extend_from_slice(ciphertext);
        bytes
    }

    #[test]
    fn test_encrypted_keyset_from_path_parsing_structure() -> Result<()> {
        let salt = [1u8; 8];
        let hmac = [2u8; 32];
        let iv = [3u8; 16];
        let ciphertext = [4u8; 224]; // Example length for 3x64bit keys + padding
        let dummy_bytes = create_dummy_keyset_bytes(&salt, &hmac, &iv, &ciphertext);

        let dir = tempdir()?;
        let file_path = dir.path().join("encryptedkeyset.dat");
        let mut temp_file = File::create(&file_path)?;
        temp_file.write_all(&dummy_bytes)?;

        let keyset = EncryptedKeySet::from_path(&file_path)?;
        // No decryption here, just testing that from_path can read and an EncryptedKeySet struct is formed.
        // Internal fields of EncryptedKeySet are private, so we can't directly check them here
        // without exposing them or adding accessors. This test mainly checks if `from_path` runs.
        // A more thorough test would involve `decrypt` with known good data.
        Ok(())
    }

    #[test]
    fn test_encrypted_keyset_from_path_too_short() {
        let dummy_bytes = b"ARQ_ENCRYPTED_MASTER_KEYS_TOO_SHORT".to_vec();
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("encryptedkeyset.dat");
        let mut temp_file = File::create(&file_path).unwrap();
        temp_file.write_all(&dummy_bytes).unwrap();

        let result = EncryptedKeySet::from_path(&file_path);
        assert!(result.is_err());
        // Check for specific error type if possible/desired
    }

    #[test]
    fn test_encrypted_keyset_from_path_bad_header() {
        let salt = [1u8; 8];
        let hmac = [2u8; 32];
        let iv = [3u8; 16];
        let ciphertext = [4u8; 64];
        let mut dummy_bytes = Vec::new();
        dummy_bytes.extend_from_slice(b"BAD_HEADER_FOR_ENCRYPTED_KEYS"); // Wrong header
        dummy_bytes.extend_from_slice(&salt);
        dummy_bytes.extend_from_slice(&hmac);
        dummy_bytes.extend_from_slice(&iv);
        dummy_bytes.extend_from_slice(&ciphertext);

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("encryptedkeyset.dat");
        let mut temp_file = File::create(&file_path).unwrap();
        temp_file.write_all(&dummy_bytes).unwrap();

        let result = EncryptedKeySet::from_path(&file_path);
        assert!(result.is_err());
    }

    // test_encrypted_keyset_decryption_valid_password() -> Requires actual encrypted data and password
    // test_encrypted_keyset_decryption_invalid_password() -> Requires actual encrypted data
    // test_encrypted_keyset_decryption_tampered_hmac() -> Requires actual encrypted data
}


use arq::arq7_format::Arq7EncryptedObject;

mod arq7_encrypted_object_tests {
    use super::*;

    // Helper to create dummy Arq7EncryptedObject bytes
    fn create_dummy_arq7_object_bytes(hmac: &[u8; 32], master_iv: &[u8; 16], enc_data_iv_session: &[u8; 64], ciphertext: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ARQO"); // 4 bytes header
        bytes.extend_from_slice(hmac);
        bytes.extend_from_slice(master_iv);
        bytes.extend_from_slice(enc_data_iv_session);
        bytes.extend_from_slice(ciphertext);
        bytes
    }

    #[test]
    fn test_arq7_encrypted_object_from_bytes_structure() -> Result<()> {
        let hmac = [1u8; 32];
        let master_iv = [2u8; 16];
        let enc_data_iv_session = [3u8; 64];
        let ciphertext = [4u8; 128]; // Example length
        let dummy_bytes = create_dummy_arq7_object_bytes(&hmac, &master_iv, &enc_data_iv_session, &ciphertext);

        let arq_object = Arq7EncryptedObject::from_bytes(&dummy_bytes)?;
        // Internal fields are private, this test mainly checks if `from_bytes` runs with correct structure.
        // Further tests would involve `decrypt` with known good data.
        Ok(())
    }

    #[test]
    fn test_arq7_encrypted_object_from_bytes_too_short() {
        let cases = vec![
            b"ARQ".to_vec(), // Too short for header
            b"ARQO".to_vec(), // Too short for HMAC
            [&b"ARQO"[..], &[0u8; 31]].concat(), // Too short for HMAC
            [&b"ARQO"[..], &[0u8; 32]].concat(), // Too short for master_iv
            [&b"ARQO"[..], &[0u8; 32], &[0u8; 15]].concat(), // Too short for master_iv
            [&b"ARQO"[..], &[0u8; 32], &[0u8; 16]].concat(), // Too short for enc_data_iv_session
            [&b"ARQO"[..], &[0u8; 32], &[0u8; 16], &[0u8; 63]].concat(), // Too short for enc_data_iv_session
        ];
        for case in cases {
            let result = Arq7EncryptedObject::from_bytes(&case);
            assert!(result.is_err(), "Expected error for bytestring: {:?}", case);
        }
    }

    #[test]
    fn test_arq7_encrypted_object_from_bytes_bad_header() {
        let hmac = [1u8; 32];
        let master_iv = [2u8; 16];
        let enc_data_iv_session = [3u8; 64];
        let ciphertext = [4u8; 64];
        let mut dummy_bytes = Vec::new();
        dummy_bytes.extend_from_slice(b"BADH"); // Wrong header
        dummy_bytes.extend_from_slice(&hmac);
        dummy_bytes.extend_from_slice(&master_iv);
        dummy_bytes.extend_from_slice(&enc_data_iv_session);
        dummy_bytes.extend_from_slice(&ciphertext);

        let result = Arq7EncryptedObject::from_bytes(&dummy_bytes);
        assert!(result.is_err());
    }
    // TODO: Add tests for Arq7EncryptedObject::decrypt (requires valid encrypted test data)
}


use arq::arq7_format::{BackupRecord, BackupPlanJson, NodeJson, BlobLoc, Arq5TreeBlobKey, BackupFolderPlanJson};
use arq::plist::to_writer_xml; // To create XML plist data for testing
use arq::compression::{lz4_compress_with_prefix, lz4_decompress_with_prefix}; // For test data prep
use std::collections::BTreeMap;

// --- BackupRecord Tests ---
mod backup_record_tests {
    use super::*;
    use arq::arq7_format::{EncryptedKeySetPlaintext, Arq7EncryptedObject}; // For encrypting test data

    // Helper to create a sample BackupRecord for serialization to plist
    fn sample_backup_record() -> BackupRecord {
        let mut backup_folder_plans = BTreeMap::new();
        backup_folder_plans.insert("folder_uuid_1".to_string(), BackupFolderPlanJson {
            backup_folder_uuid: "folder_uuid_1".to_string(),
            local_path: "/path/to/folder1".to_string(),
            name: "Folder1".to_string(),
        });

        BackupRecord {
            archived: 0,
            arq_version: "7.5.0".to_string(),
            backup_folder_uuid: "some_folder_uuid".to_string(),
            backup_plan_json: BackupPlanJson {
                active: 1,
                name: "Test Plan".to_string(),
                plan_uuid: "some_plan_uuid".to_string(),
                is_encrypted: false, // Keep it simple for base plist test
                backup_folder_plans_by_uuid: backup_folder_plans,
            },
            backup_plan_uuid: "some_plan_uuid".to_string(),
            computer_os_type: Some(1), // 1 for macOS, 2 for Windows
            copied_from_commit: false,
            copied_from_snapshot: false,
            creation_date: 1678886400, // Some timestamp
            disk_identifier: Some("disk_id_123".to_string()),
            error_count: 0,
            is_complete: true,
            local_mount_point: Some("/".to_string()),
            local_path: "/Users/test/docs".to_string(),
            node: Some(NodeJson {
                change_time_nsec: 0,
                change_time_sec: 0,
                computer_os_type: Some(1),
                contained_files_count: Some(10),
                creation_time_nsec: 0,
                creation_time_sec: 0,
                data_blob_locs: Vec::new(),
                deleted: Some(false),
                is_tree: true,
                item_size: 1024,
                mac_st_dev: Some(0),
                mac_st_flags: Some(0),
                mac_st_gid: Some(0),
                mac_st_ino: Some(0),
                mac_st_mode: Some(0),
                mac_st_nlink: Some(0),
                mac_st_rdev: Some(0),
                mac_st_uid: Some(0),
                modification_time_nsec: 0,
                modification_time_sec: 0,
                tree_blob_loc: Some(BlobLoc {
                    blob_identifier: "tree_blob_id".to_string(),
                    is_packed: true,
                    relative_path: "/pack/path".to_string(),
                    offset: 0,
                    length: 100,
                    stretch_encryption_key: true,
                    compression_type: 2, // LZ4
                }),
                win_attrs: None,
                xattrs_blob_locs: Vec::new(),
            }),
            relative_path: "/backup/path/record".to_string(),
            storage_class: "STANDARD".to_string(),
            version: 100,
            volume_name: Some("Macintosh HD".to_string()),
            arq5_bucket_xml: None,
            arq5_tree_blob_key: None,
        }
    }

    #[test]
    fn test_backup_record_plist_serialization_deserialization() -> Result<()> {
        let record = sample_backup_record();
        let mut buf = Vec::new();
        to_writer_xml(&mut buf, &record)?; // Serialize to XML plist

        // Now try to deserialize it back using the same logic BackupRecord::from_path_and_keys would use internally
        // (after potential decryption/decompression)
        let deserialized_record: BackupRecord = arq::plist::from_bytes(&buf)
            .map_err(|e| arq::error::Error::PlistDecode(format!("Plist deserde failed: {}", e)))?;

        assert_eq!(deserialized_record.arq_version, record.arq_version);
        assert_eq!(deserialized_record.local_path, record.local_path);
        assert!(deserialized_record.node.is_some());
        assert_eq!(deserialized_record.node.as_ref().unwrap().item_size, record.node.as_ref().unwrap().item_size);

        Ok(())
    }

    #[test]
    fn test_backup_record_from_path_unencrypted_lz4() -> Result<()> {
        let record_data = sample_backup_record();
        let mut plist_bytes = Vec::new();
        to_writer_xml(&mut plist_bytes, &record_data)?;

        let compressed_plist_bytes = lz4_compress_with_prefix(&plist_bytes)?;

        let dir = tempdir()?;
        let file_path = dir.path().join("test.backuprecord");
        let mut temp_file = File::create(&file_path)?;
        temp_file.write_all(&compressed_plist_bytes)?;
        drop(temp_file); // Close the file

        let parsed_record = BackupRecord::from_path_and_keys(&file_path, false, None)?;

        assert_eq!(parsed_record.arq_version, record_data.arq_version);
        assert_eq!(parsed_record.local_path, record_data.local_path);
        assert!(parsed_record.node.is_some());
        assert_eq!(parsed_record.node.as_ref().unwrap().item_size, record_data.node.as_ref().unwrap().item_size);
        assert_eq!(
            parsed_record.node.as_ref().unwrap().tree_blob_loc.as_ref().unwrap().blob_identifier,
            "tree_blob_id"
        );

        Ok(())
    }

    // TODO: test_backup_record_from_path_encrypted_lz4()
    // This would require:
    // 1. Taking plist_bytes (XML plist).
    // 2. LZ4 compressing it with prefix: `compressed_bytes = lz4_compress_with_prefix(&plist_bytes)?`
    // 3. Encrypting `compressed_bytes` using a dummy Arq7EncryptedObject structure.
    //    - This means generating a dummy session key & data IV.
    //    - Encrypting (data_iv + session_key) with dummy_keys.encryption_key and dummy_master_iv.
    //    - Encrypting `compressed_bytes` with session_key and data_iv.
    //    - Calculating HMAC of (master_iv + encrypted_session_stuff + ciphertext_of_compressed_bytes) using dummy_keys.hmac_key.
    //    - Assembling into ARQO format: ARQO_header + HMAC + master_IV + encrypted_session_stuff + ciphertext_of_compressed_bytes.
    // 4. Writing these final bytes to a temp file.
    // 5. Calling BackupRecord::from_path_and_keys with `is_globally_encrypted = true` and `dummy_keys`.
    // 6. Asserting the parsed record.
    // This is non-trivial due to needing a compatible encryption process for the test data.
}

// --- PackObject Tests ---
mod pack_object_tests {
    use super::*;
    use arq::packset::PackObject;
    use arq::compression::CompressionType;
    use arq::arq7_format::{EncryptedKeySetPlaintext, Arq7EncryptedObject};
    use arq::object_encryption::{EncryptedObject as Arq5EncryptedObject}; // Renamed in packset.rs

    // Helper to create dummy Arq5EncryptedObject bytes (ARQO format)
    // This function would need to perform actual AES encryption and HMAC calculation.
    // For now, it's a placeholder structure.
    fn create_dummy_arq5_encrypted_object_bytes(
        plaintext: &[u8],
        aes_key: &[u8; 32], // For Arq5, usually from master_keys[0]
        hmac_key: &[u8; 32]  // For Arq5, usually from master_keys[1]
    ) -> Result<Vec<u8>> {
        // Simplified: In a real test, this would involve:
        // 1. Generate random data_iv, session_key.
        // 2. Encrypt plaintext with session_key, data_iv -> ciphertext.
        // 3. Encrypt (data_iv + session_key) with aes_key (as master_key_for_session_key_encryption) and a random master_iv.
        // 4. HMAC (master_iv + encrypted_session_data + ciphertext) using hmac_key.
        // 5. Assemble: "ARQO" + HMAC + master_IV + encrypted_session_data + ciphertext.
        // This is too complex for a quick test setup without proper crypto helpers.
        // For now, let's assume we have a pre-encrypted blob for testing or test unencrypted path.

        // This placeholder will make the test fail if actual decryption is called.
        // It's just to test the structure of calling get_content_arq5.
        // To make it pass a structural test (not crypto), it needs to be a valid ARQO structure.
        let header = b"ARQO";
        let dummy_hmac = [0u8; 32];
        let dummy_master_iv = [0u8; 16];
        let dummy_enc_session_key = [0u8; 64]; // Padded IV (16) + SessionKey (32) = 48, padded to 64

        // For a simple test of non-crypto parts, let ciphertext be the original plaintext
        // This will fail decryption validation but allows testing flow.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(&dummy_hmac);
        bytes.extend_from_slice(&dummy_master_iv);
        bytes.extend_from_slice(&dummy_enc_session_key);
        bytes.extend_from_slice(plaintext); // This is not actually encrypted plaintext
        Ok(bytes)
    }

    // Test for unencrypted Arq7 content within a PackObject
    #[test]
    fn test_pack_object_get_content_arq7_unencrypted_lz4() -> Result<()> {
        let original_data = b"Hello Arq7 Unencrypted LZ4 Data";
        let compressed_data = lz4_compress_with_prefix(original_data)?;

        let pack_object = PackObject {
            mimetype: "application/octet-stream".to_string(),
            name: "test_object_unencrypted_lz4".to_string(),
            object_data_raw: compressed_data,
        };

        // Dummy keys, not used since is_globally_encrypted is false
        let dummy_keys = EncryptedKeySetPlaintext {
            encryption_version: 3,
            encryption_key: vec![0; 64],
            hmac_key: vec![0; 64],
            blob_identifier_salt: vec![0; 64],
        };

        let retrieved_content = pack_object.get_content_arq7(
            CompressionType::LZ4, // This is how it would be specified from BlobLoc.compressionType = 2
            &dummy_keys,
            false, // Not globally encrypted
        )?;

        assert_eq!(retrieved_content, original_data);
        Ok(())
    }

    #[test]
    fn test_pack_object_get_content_arq7_unencrypted_none() -> Result<()> {
        let original_data = b"Hello Arq7 Unencrypted NoCompression Data";

        let pack_object = PackObject {
            mimetype: "text/plain".to_string(),
            name: "test_object_unencrypted_none".to_string(),
            object_data_raw: original_data.to_vec(), // Already prefixed if LZ4, direct if None
        };

        let dummy_keys = EncryptedKeySetPlaintext {
            encryption_version: 3,
            encryption_key: vec![0; 64],
            hmac_key: vec![0; 64],
            blob_identifier_salt: vec![0; 64],
        };

        let retrieved_content = pack_object.get_content_arq7(
            CompressionType::None, // BlobLoc.compressionType = 0
            &dummy_keys,
            false, // Not globally encrypted
        )?;

        assert_eq!(retrieved_content, original_data);
        Ok(())
    }

    // TODO: test_pack_object_get_content_arq7_encrypted_lz4()
    // - Will require creating a valid Arq7EncryptedObject byte stream (ARQO wrapped, HMACed, AESed)
    //   containing LZ4-prefixed compressed data.
    // - Then test `get_content_arq7` with `is_globally_encrypted = true`.

    // TODO: test_pack_object_get_content_arq5_encrypted_lz4()
    // - Will require creating a valid Arq5EncryptedObject byte stream.
    // - Then test `get_content_arq5`.
}


// --- Binary Parsing Tests ---
#[cfg(test)]
mod binary_parsing_tests {
    use super::*; // For Result
    use arq::arq7_format::{BlobLoc, NodeBin, TreeBin};
    use arq::type_utils::ArqRead;
    use byteorder::{WriteBytesExt, BigEndian};
    use std::io::Cursor; // For creating a reader from Vec<u8>

    // Helper to create Arq-formatted string bytes: 0x01 (present) + len (u64 BE) + string_bytes
    fn arq_string_bytes(s: &str) -> Vec<u8> {
        let mut bytes = vec![0x01]; // Present
        bytes.write_u64::<BigEndian>(s.len() as u64).unwrap();
        bytes.extend_from_slice(s.as_bytes());
        bytes
    }

    fn arq_string_empty_bytes() -> Vec<u8> {
        vec![0x00] // Not present
    }

    fn arq_bool_bytes(b: bool) -> Vec<u8> {
        vec![if b { 0x01 } else { 0x00 }]
    }

    fn arq_u32_bytes(val: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_u32::<BigEndian>(val).unwrap();
        bytes
    }

    fn arq_u64_bytes(val: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_u64::<BigEndian>(val).unwrap();
        bytes
    }

    fn arq_i32_bytes(val: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_i32::<BigEndian>(val).unwrap();
        bytes
    }

    fn arq_i64_bytes(val: i64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_i64::<BigEndian>(val).unwrap();
        bytes
    }

    #[test]
    fn test_blob_loc_from_reader_full() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_string_bytes("blob_id_123"));
        data.extend(arq_bool_bytes(true)); // is_packed
        data.extend(arq_string_bytes("/path/to/pack.pack"));
        data.extend(arq_u64_bytes(1024)); // offset
        data.extend(arq_u64_bytes(2048)); // length
        data.extend(arq_bool_bytes(true)); // stretch_encryption_key
        data.extend(arq_u32_bytes(2));    // compression_type (LZ4)

        let mut cursor = Cursor::new(data);
        let blob_loc = BlobLoc::from_reader(&mut cursor)?;

        assert_eq!(blob_loc.blob_identifier, "blob_id_123");
        assert!(blob_loc.is_packed);
        assert_eq!(blob_loc.relative_path, "/path/to/pack.pack");
        assert_eq!(blob_loc.offset, 1024);
        assert_eq!(blob_loc.length, 2048);
        assert!(blob_loc.stretch_encryption_key);
        assert_eq!(blob_loc.compression_type, 2);
        Ok(())
    }

    #[test]
    fn test_blob_loc_from_reader_empty_relative_path() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_string_bytes("blob_id_456"));
        data.extend(arq_bool_bytes(false));
        data.extend(arq_string_empty_bytes());
        data.extend(arq_u64_bytes(0));
        data.extend(arq_u64_bytes(512));
        data.extend(arq_bool_bytes(false));
        data.extend(arq_u32_bytes(0));

        let mut cursor = Cursor::new(data);
        let blob_loc = BlobLoc::from_reader(&mut cursor)?;

        assert_eq!(blob_loc.blob_identifier, "blob_id_456");
        assert!(!blob_loc.is_packed);
        assert_eq!(blob_loc.relative_path, "");
        assert_eq!(blob_loc.length, 512);
        assert!(!blob_loc.stretch_encryption_key);
        assert_eq!(blob_loc.compression_type, 0);
        Ok(())
    }

    #[test]
    fn test_node_bin_from_reader_file() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_bool_bytes(false)); // is_tree = false
        data.extend(arq_u32_bytes(1));      // computer_os_type (macOS)

        data.extend(arq_u64_bytes(1));      // data_blob_locs_count = 1
            data.extend(arq_string_bytes("data_blob_1"));
            data.extend(arq_bool_bytes(true)); data.extend(arq_string_bytes("/pack/data.pack"));
            data.extend(arq_u64_bytes(4096)); data.extend(arq_u64_bytes(100));
            data.extend(arq_bool_bytes(true)); data.extend(arq_u32_bytes(2));

        data.extend(arq_bool_bytes(false)); // acl_blob_loc_is_not_nil = false
        data.extend(arq_u64_bytes(0));      // xattrs_blob_loc_count = 0

        data.extend(arq_u64_bytes(100)); // item_size
        data.extend(arq_u64_bytes(0));   // contained_files_count (0 for file)
        data.extend(arq_i64_bytes(1600000000)); data.extend(arq_i64_bytes(0)); // mtime
        data.extend(arq_i64_bytes(1600000001)); data.extend(arq_i64_bytes(0)); // ctime
        data.extend(arq_i64_bytes(1600000002)); data.extend(arq_i64_bytes(0)); // create_time
        data.extend(arq_string_bytes("user")); data.extend(arq_string_bytes("group"));
        data.extend(arq_bool_bytes(false)); // deleted
        data.extend(arq_i32_bytes(0)); data.extend(arq_u64_bytes(0)); data.extend(arq_u32_bytes(0o100644));
        data.extend(arq_u32_bytes(1)); data.extend(arq_u32_bytes(501)); data.extend(arq_u32_bytes(20));
        data.extend(arq_i32_bytes(0)); data.extend(arq_i32_bytes(0));
        data.extend(arq_u32_bytes(0)); // win_attrs
        // No win_reparse for tree_version = 1

        let mut cursor = Cursor::new(data);
        let node_bin = NodeBin::from_reader(&mut cursor, 1)?; // tree_version = 1

        assert!(!node_bin.is_tree);
        assert!(node_bin.tree_blob_loc.is_none());
        assert_eq!(node_bin.data_blob_locs.len(), 1);
        assert_eq!(node_bin.data_blob_locs[0].blob_identifier, "data_blob_1");
        assert_eq!(node_bin.item_size, 100);
        assert!(node_bin.win_reparse_tag.is_none());
        Ok(())
    }

    #[test]
    fn test_node_bin_from_reader_tree_v2_reparse() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_bool_bytes(true)); // is_tree = true
            data.extend(arq_string_bytes("tree_blob_for_reparse"));
            data.extend(arq_bool_bytes(false)); data.extend(arq_string_empty_bytes());
            data.extend(arq_u64_bytes(0)); data.extend(arq_u64_bytes(0));
            data.extend(arq_bool_bytes(false)); data.extend(arq_u32_bytes(0));
        data.extend(arq_u32_bytes(2)); // computer_os_type (Windows)
        data.extend(arq_u64_bytes(0)); data.extend(arq_bool_bytes(false));
        data.extend(arq_u64_bytes(0));
        data.extend(arq_u64_bytes(0)); data.extend(arq_u64_bytes(5));
        data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
        data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
        data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
        data.extend(arq_string_empty_bytes()); data.extend(arq_string_empty_bytes());
        data.extend(arq_bool_bytes(false));
        data.extend(arq_i32_bytes(0)); data.extend(arq_u64_bytes(0)); data.extend(arq_u32_bytes(0o040755));
        data.extend(arq_u32_bytes(1)); data.extend(arq_u32_bytes(0)); data.extend(arq_u32_bytes(0));
        data.extend(arq_i32_bytes(0)); data.extend(arq_i32_bytes(0));
        data.extend(arq_u32_bytes(16)); // win_attrs (Directory)
        data.extend(arq_u32_bytes(0x80000000u32));
        data.extend(arq_bool_bytes(true));

        let mut cursor = Cursor::new(data);
        let node_bin = NodeBin::from_reader(&mut cursor, 2)?; // tree_version = 2

        assert!(node_bin.is_tree);
        assert!(node_bin.tree_blob_loc.is_some());
        assert_eq!(node_bin.win_reparse_tag.unwrap(), 0x80000000u32);
        assert!(node_bin.win_reparse_point_is_directory.unwrap());
        Ok(())
    }

    #[test]
    fn test_tree_bin_from_reader() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_u32_bytes(2)); // version = 2
        data.extend(arq_u64_bytes(1)); // childNodesByNameCount = 1
            data.extend(arq_string_bytes("child_file.txt"));
            // Child 1 NodeBin (file, tree_version=2 from parent)
            data.extend(arq_bool_bytes(false)); data.extend(arq_u32_bytes(1));
            data.extend(arq_u64_bytes(0)); data.extend(arq_bool_bytes(false));
            data.extend(arq_u64_bytes(0)); data.extend(arq_u64_bytes(123));
            data.extend(arq_u64_bytes(0)); data.extend(arq_i64_bytes(0));
            data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
            data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
            data.extend(arq_i64_bytes(0)); data.extend(arq_string_empty_bytes());
            data.extend(arq_string_empty_bytes()); data.extend(arq_bool_bytes(false));
            data.extend(arq_i32_bytes(0)); data.extend(arq_u64_bytes(0)); data.extend(arq_u32_bytes(0));
            data.extend(arq_u32_bytes(0)); data.extend(arq_u32_bytes(0)); data.extend(arq_u32_bytes(0));
            data.extend(arq_i32_bytes(0)); data.extend(arq_i32_bytes(0));
            data.extend(arq_u32_bytes(0)); data.extend(arq_u32_bytes(0));
            data.extend(arq_bool_bytes(false));

        let mut cursor = Cursor::new(data);
        let tree_bin = TreeBin::from_reader(&mut cursor)?;

        assert_eq!(tree_bin.version, 2);
        assert_eq!(tree_bin.child_nodes_by_name.len(), 1);
        let child_node = tree_bin.child_nodes_by_name.get("child_file.txt").unwrap();
        assert!(!child_node.is_tree);
        assert_eq!(child_node.item_size, 123);
        Ok(())
    }
}


// --- Arq7BackupSet Tests ---
mod arq7_backup_set_tests {
    use super::*;
    use arq::arq7_format::Arq7BackupSet;
    use std::fs::{self, create_dir_all};

    // Helper to create a basic backupconfig.json
    fn create_backup_config_file(path: &std::path::Path, is_encrypted: bool) -> Result<()> {
        let json_content = format!(r#"
        {{
            "blobIdentifierType": 2, "maxPackedItemLength": 256000, "backupName": "Test Backup Set",
            "isWORM": false, "containsGlacierArchives": false, "additionalUnpackedBlobDirs": [],
            "chunkerVersion": 3, "computerName": "TestComputer", "computerSerial": "unused",
            "blobStorageClass": "STANDARD", "isEncrypted": {}
        }}"#, is_encrypted);
        let mut file = File::create(path.join("backupconfig.json"))?;
        write!(file, "{}", json_content)?;
        Ok(())
    }

    // Helper to create a dummy encryptedkeyset.dat (structurally, not cryptographically valid for decryption)
    fn create_dummy_encrypted_keyset_file(path: &std::path::Path) -> Result<()> {
        let salt = [1u8; 8];
        let hmac = [2u8; 32];
        let iv = [3u8; 16];
        let ciphertext = [4u8; 224]; // Example length

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ARQ_ENCRYPTED_MASTER_KEYS");
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&hmac);
        bytes.extend_from_slice(&iv);
        bytes.extend_from_slice(&ciphertext);

        let mut file = File::create(path.join("encryptedkeyset.dat"))?;
        file.write_all(&bytes)?;
        Ok(())
    }

    // Helper to create backupfolders.json
    fn create_backup_folders_index_file(path: &std::path::Path) -> Result<()> {
        let json_content = r#"
        {
            "standardObjectDirs": ["/TestBackupSet/standardobjects"],
            "standardIAObjectDirs": [], "onezoneIAObjectDirs": [],
            "s3GlacierObjectDirs": [], "s3DeepArchiveObjectDirs": [],
            "importedFrom": null
        }"#;
        let mut file = File::create(path.join("backupfolders.json"))?;
        write!(file, "{}", json_content)?;
        Ok(())
    }

    // Helper to create a backupfolder.json for a given UUID
    fn create_backup_folder_config_file(base_path: &std::path::Path, uuid: &str, name: &str, local_path_str: &str) -> Result<()> {
        let folder_path = base_path.join("backupfolders").join(uuid);
        create_dir_all(&folder_path)?;
        let json_content = format!(r#"
        {{
            "localPath": "{}", "migratedFromArq60": false, "storageClass": "STANDARD",
            "diskIdentifier": "TEST_DISK", "uuid": "{}", "migratedFromArq5": false,
            "localMountPoint": "/", "name": "{}"
        }}"#, local_path_str, uuid, name);
        let mut file = File::create(folder_path.join("backupfolder.json"))?;
        write!(file, "{}", json_content)?;
        Ok(())
    }


    #[test]
    fn test_arq7_backup_set_load_unencrypted() -> Result<()> {
        let dir = tempdir()?;
        let base_path = dir.path();
        create_backup_config_file(base_path, false)?;
        create_backup_folders_index_file(base_path)?;

        let backup_set = Arq7BackupSet::load(base_path, None)?;
        assert!(!backup_set.config.is_encrypted);
        assert!(backup_set.keys.is_none());
        assert_eq!(backup_set.backup_folders_index.standard_object_dirs.len(), 1);
        Ok(())
    }

    #[test]
    fn test_arq7_backup_set_load_encrypted_requires_password() -> Result<()> {
        let dir = tempdir()?;
        let base_path = dir.path();
        create_backup_config_file(base_path, true)?; // is_encrypted = true
        // No encryptedkeyset.dat needed for this specific error check path
        create_backup_folders_index_file(base_path)?;

        let result = Arq7BackupSet::load(base_path, None); // No password provided
        assert!(result.is_err());
        // TODO: Check specific error type Error::Input("Password required...")
        Ok(())
    }

    // test_arq7_backup_set_load_encrypted_with_password() would require a *valid* encryptedkeyset.dat
    // and a password that can decrypt it. Marked as TODO due to test data complexity.

    #[test]
    fn test_list_backup_folder_configs() -> Result<()> {
        let dir = tempdir()?;
        let base_path = dir.path();
        create_backup_config_file(base_path, false)?;
        create_backup_folders_index_file(base_path)?;

        // Create some backup folder configs
        let uuid1 = "uuid-folder-1";
        let uuid2 = "uuid-folder-2";
        create_backup_folder_config_file(base_path, uuid1, "Folder 1", "/docs")?;
        create_backup_folder_config_file(base_path, uuid2, "Folder 2", "/pics")?;
        // Create an empty dir that shouldn't be picked up
        create_dir_all(base_path.join("backupfolders").join("not-a-folder-config"))?;
        // Create a dir with no backupfolder.json
        create_dir_all(base_path.join("backupfolders").join("uuid-folder-3-empty"))?;


        let backup_set = Arq7BackupSet::load(base_path, None)?;
        let folder_configs = backup_set.list_backup_folder_configs()?;

        assert_eq!(folder_configs.len(), 2);
        assert!(folder_configs.iter().any(|fc| fc.uuid == uuid1 && fc.name == "Folder 1"));
        assert!(folder_configs.iter().any(|fc| fc.uuid == uuid2 && fc.name == "Folder 2"));

        Ok(())
    }

    #[test]
    fn test_list_backup_folder_configs_empty() -> Result<()> {
        let dir = tempdir()?;
        let base_path = dir.path();
        create_backup_config_file(base_path, false)?;
        create_backup_folders_index_file(base_path)?;
        // No backupfolders subdirectories created

        let backup_set = Arq7BackupSet::load(base_path, None)?;
        let folder_configs = backup_set.list_backup_folder_configs()?;
        assert!(folder_configs.is_empty());
        Ok(())
    }

    // TODO: test_list_backup_records()
    // - Setup mock backup set with a folder config.
    // - Create sample .backuprecord files within backupfolders/UUID/backuprecords/SUBDIR/
    //   - These files need to be valid plists (e.g. XML), LZ4 compressed.
    //   - If testing encryption, also ARQO encrypted.
    // - Call list_backup_records and verify the output.
    // - Test sorting by date.
    // - Test case with no records.
}


// Example of how a crypto test might look (needs actual data)
/*
use arq::arq7_format::EncryptedKeySet;
// ... other necessary imports ...

#[test]
fn test_encrypted_key_set_decryption_valid_password() {
    // These would be actual bytes from a test file or a known constant byte array
    let sample_keyset_bytes: &[u8] = &[
        // b"ARQ_ENCRYPTED_MASTER_KEYS" (25 bytes)
        0x41, 0x52, 0x51, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x5f, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52, 0x5f, 0x4b, 0x45, 0x59, 0x53,
        // salt (8 bytes) - example
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        // hmac_sha256 (32 bytes) - placeholder, would be actual HMAC
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        // iv (16 bytes) - example
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        // ciphertext (e.g., 208 bytes for 3x64 byte keys + padding) - placeholder
        // This would be AES-256-CBC(PKCS7) encrypted plaintext of EncryptedKeySetPlaintext structure
        // (version_be(4) + len64_be(8) + key1(64) + len64_be(8) + key2(64) + len64_be(8) + salt(64)) = 4+8+64+8+64+8+64 = 220 bytes
        // Padded to AES block size (16), so 224 bytes if no other metadata.
        // The plaintext keyset is 3*64 + 3*8 + 4 = 192 + 24 + 4 = 220 bytes.
        // 224 bytes of ciphertext.
        // ... (actual ciphertext bytes) ...
    ];
    let password = "testpassword";

    // Setup: Write sample_keyset_bytes to a temporary file
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("encryptedkeyset.dat");
    let mut temp_file = File::create(&file_path).unwrap();
    temp_file.write_all(sample_keyset_bytes).unwrap();

    let keyset = EncryptedKeySet::from_path(&file_path).unwrap();
    let plaintext_keys = keyset.decrypt(password);

    // This test would fail without actual valid encrypted data and HMAC
    // assert!(plaintext_keys.is_ok());
    // let keys = plaintext_keys.unwrap();
    // assert_eq!(keys.encryption_version, 3);
    // assert_eq!(keys.encryption_key.len(), 64);
    // assert_eq!(keys.hmac_key.len(), 64);
    // assert_eq!(keys.blob_identifier_salt.len(), 64);
    // Further asserts on actual key bytes if known.
}
*/
