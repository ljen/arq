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

    // Parse directly from string for debugging this specific test's JSON issue
    let config: BackupConfig = serde_json::from_str(json_content.trim())
        .map_err(|e| arq::error::Error::JsonDecode(format!("Direct from_str failed for minimal: {} (JSON: {})", e, json_content.trim())))?;

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

    // dir.close()?; // dir is not used in this modified test
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
    write!(temp_file, "{}", json_content.trim())?;

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
    write!(temp_file, "{}", json_content.trim())?;

    let bf = BackupFolders::from_path(&file_path)?;
    assert_eq!(bf.standard_object_dirs, vec!["/some/path/standardobjects".to_string()]);
    assert!(bf.standard_ia_object_dirs.is_empty());
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
        "standardIaObjectDirs": ["/path1/standardiaobjects"],
        "onezoneIaObjectDirs": ["/path1/onezoneiaobjects"],
        "s3GlacierObjectDirs": ["/path1/s3glacierobjects"],
        "s3DeepArchiveObjectDirs": ["/path1/s3deeparchiveobjects"],
        "importedFrom": "5.x"
    }
    "#;
    let dir = tempdir()?;
    let file_path = dir.path().join("backupfolders.json");
    let mut temp_file = File::create(&file_path)?;
    write!(temp_file, "{}", json_content.trim())?;

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
    write!(temp_file, "{}", json_content.trim())?;

    let bfc = BackupFolder::from_path(&file_path)?;
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
// use std::io::Cursor; // Moved into modules that use it

mod encrypted_keyset_tests {
    use super::*;
    use std::io::Cursor;

    fn create_dummy_keyset_bytes(salt: &[u8; 8], hmac: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ARQ_ENCRYPTED_MASTER_KEYS");
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
        let ciphertext = [4u8; 224];
        let dummy_bytes = create_dummy_keyset_bytes(&salt, &hmac, &iv, &ciphertext);

        let dir = tempdir()?;
        let file_path = dir.path().join("encryptedkeyset.dat");
        let mut temp_file = File::create(&file_path)?;
        temp_file.write_all(&dummy_bytes)?;

        let _keyset = EncryptedKeySet::from_path(&file_path)?;
        Ok(())
    }

    #[test]
    fn test_encrypted_keyset_from_path_too_short() {
        let dummy_bytes = b"ARQ_ENCRYPTED_MASTER_KEYS_TOO_SHORT".to_vec();
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("encryptedkeyset.dat");
        let mut temp_file = File::create(&file_path).unwrap();
        temp_file.write_all(&dummy_bytes).unwrap();
        drop(temp_file);
        let result = EncryptedKeySet::from_path(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_keyset_from_path_bad_header() {
        let salt = [1u8; 8];
        let hmac = [2u8; 32];
        let iv = [3u8; 16];
        let ciphertext = [4u8; 64];
        let mut dummy_bytes = Vec::new();
        dummy_bytes.extend_from_slice(b"BAD_HEADER_FOR_ENCRYPTED_KEYS");
        dummy_bytes.extend_from_slice(&salt);
        dummy_bytes.extend_from_slice(&hmac);
        dummy_bytes.extend_from_slice(&iv);
        dummy_bytes.extend_from_slice(&ciphertext);

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("encryptedkeyset.dat");
        let mut temp_file = File::create(&file_path).unwrap();
        temp_file.write_all(&dummy_bytes).unwrap();
        drop(temp_file);
        let result = EncryptedKeySet::from_path(&file_path);
        assert!(result.is_err());
    }
}

mod arq7_encrypted_object_tests {
    use super::*;
    use arq::arq7_format::Arq7EncryptedObject;

    fn create_dummy_arq7_object_bytes(hmac: &[u8; 32], master_iv: &[u8; 16], enc_data_iv_session: &[u8; 64], ciphertext: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ARQO");
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
        let ciphertext = [4u8; 128];
        let dummy_bytes = create_dummy_arq7_object_bytes(&hmac, &master_iv, &enc_data_iv_session, &ciphertext);

        let _arq_object = Arq7EncryptedObject::from_bytes(&dummy_bytes)?;
        Ok(())
    }

    #[test]
    fn test_arq7_encrypted_object_from_bytes_too_short() {
        let cases = vec![
            b"ARQ".to_vec(), b"ARQO".to_vec(), [&b"ARQO"[..], &[0u8; 31]].concat(),
            [&b"ARQO"[..], &[0u8; 32]].concat(), [&b"ARQO"[..], &[0u8; 32], &[0u8; 15]].concat(),
            [&b"ARQO"[..], &[0u8; 32], &[0u8; 16]].concat(),
            [&b"ARQO"[..], &[0u8; 32], &[0u8; 16], &[0u8; 63]].concat(),
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
        dummy_bytes.extend_from_slice(b"BADH");
        dummy_bytes.extend_from_slice(&hmac);
        dummy_bytes.extend_from_slice(&master_iv);
        dummy_bytes.extend_from_slice(&enc_data_iv_session);
        dummy_bytes.extend_from_slice(&ciphertext);

        let result = Arq7EncryptedObject::from_bytes(&dummy_bytes);
        assert!(result.is_err());
    }
}

use arq::arq7_format::{BackupRecord, BackupPlanJson, NodeJson, BlobLoc, /*Arq5TreeBlobKey,*/ BackupFolderPlanJson}; // Arq5TreeBlobKey seems unused here
use arq::plist::to_writer_xml;
use arq::lz4::{compress as lz4_compress /*, decompress as lz4_decompress*/}; // lz4_decompress seems unused here
use std::collections::BTreeMap;

mod backup_record_tests {
    use super::*;
    // use arq::arq7_format::{EncryptedKeySetPlaintext, Arq7EncryptedObject}; // Unused in this module's current tests

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
                active: 1, name: "Test Plan".to_string(), plan_uuid: "some_plan_uuid".to_string(),
                is_encrypted: false, backup_folder_plans_by_uuid: backup_folder_plans,
            },
            backup_plan_uuid: "some_plan_uuid".to_string(),
            computer_os_type: Some(1), copied_from_commit: false, copied_from_snapshot: false,
            creation_date: 1678886400, disk_identifier: Some("disk_id_123".to_string()),
            error_count: 0, is_complete: true, local_mount_point: Some("/".to_string()),
            local_path: "/Users/test/docs".to_string(),
            node: Some(NodeJson {
                change_time_nsec: 0, change_time_sec: 0, computer_os_type: Some(1),
                contained_files_count: Some(10), creation_time_nsec: 0, creation_time_sec: 0,
                data_blob_locs: Vec::new(), deleted: Some(false), is_tree: true, item_size: 1024,
                mac_st_dev: Some(0), mac_st_flags: Some(0), mac_st_gid: Some(0), mac_st_ino: Some(0),
                mac_st_mode: Some(0), mac_st_nlink: Some(0), mac_st_rdev: Some(0), mac_st_uid: Some(0),
                modification_time_nsec: 0, modification_time_sec: 0,
                tree_blob_loc: Some(BlobLoc {
                    blob_identifier: "tree_blob_id".to_string(), is_packed: true,
                    relative_path: "/pack/path".to_string(), offset: 0, length: 100,
                    stretch_encryption_key: true, compression_type: 2,
                }),
                win_attrs: None, xattrs_blob_locs: Vec::new(),
            }),
            relative_path: "/backup/path/record".to_string(), storage_class: "STANDARD".to_string(),
            version: 100, volume_name: Some("Macintosh HD".to_string()),
            arq5_bucket_xml: None, arq5_tree_blob_key: None,
        }
    }

    #[test]
    fn test_backup_record_plist_serialization_deserialization() -> Result<()> {
        let record = sample_backup_record();
        let mut buf = Vec::new();
        to_writer_xml(&mut buf, &record)?;
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
        let compressed_plist_bytes = lz4_compress(&plist_bytes)?;
        let dir = tempdir()?;
        let file_path = dir.path().join("test.backuprecord");
        let mut temp_file = File::create(&file_path)?;
        temp_file.write_all(&compressed_plist_bytes)?;
        drop(temp_file);
        let parsed_record = BackupRecord::from_path_and_keys(&file_path, false, None)?;
        assert_eq!(parsed_record.arq_version, record_data.arq_version);
        assert_eq!(parsed_record.local_path, record_data.local_path);
        assert!(parsed_record.node.is_some());
        assert_eq!(parsed_record.node.as_ref().unwrap().item_size, record_data.node.as_ref().unwrap().item_size);
        assert_eq!(parsed_record.node.as_ref().unwrap().tree_blob_loc.as_ref().unwrap().blob_identifier, "tree_blob_id");
        Ok(())
    }
}

mod pack_object_tests {
    use super::*;
    use arq::packset::PackObject;
    // use arq::compression::CompressionType; // Not used directly
    use arq::arq7_format::{EncryptedKeySetPlaintext, Arq7EncryptedObject}; // Arq7EncryptedObject used
    // use arq::object_encryption::{EncryptedObject as Arq5EncryptedObject}; // Unused

    /*
    fn create_dummy_arq5_encrypted_object_bytes(
        plaintext: &[u8],
        _aes_key: &[u8; 32],
        _hmac_key: &[u8; 32]
    ) -> Result<Vec<u8>> {
        // ... (content commented out as function is unused)
    }
    */

    #[test]
    fn test_pack_object_get_content_arq7_unencrypted_lz4() -> Result<()> {
        let original_data = b"Hello Arq7 Unencrypted LZ4 Data";
        let compressed_data = lz4_compress(original_data)?;
        let pack_object = PackObject {
            mimetype: "application/octet-stream".to_string(),
            name: "test_object_unencrypted_lz4".to_string(),
            object_data_raw: compressed_data,
        };
        let dummy_keys = EncryptedKeySetPlaintext {
            encryption_version: 3, encryption_key: vec![0; 64],
            hmac_key: vec![0; 64], blob_identifier_salt: vec![0; 64],
        };
        let retrieved_content = pack_object.get_content_arq7(2u32, &dummy_keys, false)?;
        assert_eq!(retrieved_content, original_data);
        Ok(())
    }

    #[test]
    fn test_pack_object_get_content_arq7_unencrypted_none() -> Result<()> {
        let original_data = b"Hello Arq7 Unencrypted NoCompression Data";
        let pack_object = PackObject {
            mimetype: "text/plain".to_string(),
            name: "test_object_unencrypted_none".to_string(),
            object_data_raw: original_data.to_vec(),
        };
        let dummy_keys = EncryptedKeySetPlaintext {
            encryption_version: 3, encryption_key: vec![0; 64],
            hmac_key: vec![0; 64], blob_identifier_salt: vec![0; 64],
        };
        let retrieved_content = pack_object.get_content_arq7(0u32, &dummy_keys, false)?;
        assert_eq!(retrieved_content, original_data);
        Ok(())
    }
}

#[cfg(test)]
mod binary_parsing_tests {
    use super::*;
    use arq::arq7_format::{BlobLoc, NodeBin, TreeBin};
    use arq::type_utils::ArqRead;
    use byteorder::{WriteBytesExt, BigEndian};
    use std::io::Cursor;

    fn arq_string_bytes(s: &str) -> Vec<u8> {
        let mut bytes = vec![0x01];
        bytes.write_u64::<BigEndian>(s.len() as u64).unwrap();
        bytes.extend_from_slice(s.as_bytes());
        bytes
    }

    fn arq_string_empty_bytes() -> Vec<u8> { vec![0x00] }
    fn arq_bool_bytes(b: bool) -> Vec<u8> { vec![if b { 0x01 } else { 0x00 }] }
    fn arq_u32_bytes(val: u32) -> Vec<u8> { let mut b = Vec::new(); b.write_u32::<BigEndian>(val).unwrap(); b }
    fn arq_u64_bytes(val: u64) -> Vec<u8> { let mut b = Vec::new(); b.write_u64::<BigEndian>(val).unwrap(); b }
    // fn arq_i32_bytes(val: i32) -> Vec<u8> { let mut b = Vec::new(); b.write_i32::<BigEndian>(val).unwrap(); b } // Unused
    // fn arq_i64_bytes(val: i64) -> Vec<u8> { let mut b = Vec::new(); b.write_i64::<BigEndian>(val).unwrap(); b } // Unused

    #[test]
    fn test_blob_loc_from_reader_full() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_string_bytes("blob_id_123")); data.extend(arq_bool_bytes(true));
        data.extend(arq_string_bytes("/path/to/pack.pack")); data.extend(arq_u64_bytes(1024));
        data.extend(arq_u64_bytes(2048)); data.extend(arq_bool_bytes(true)); data.extend(arq_u32_bytes(2));
        let mut cursor = Cursor::new(data);
        let blob_loc = BlobLoc::from_reader(&mut cursor)?;
        assert_eq!(blob_loc.blob_identifier, "blob_id_123"); assert!(blob_loc.is_packed);
        assert_eq!(blob_loc.relative_path, "/path/to/pack.pack"); assert_eq!(blob_loc.offset, 1024);
        assert_eq!(blob_loc.length, 2048); assert!(blob_loc.stretch_encryption_key);
        assert_eq!(blob_loc.compression_type, 2);
        Ok(())
    }

    #[test]
    fn test_blob_loc_from_reader_empty_relative_path() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_string_bytes("blob_id_456")); data.extend(arq_bool_bytes(false));
        data.extend(arq_string_empty_bytes()); data.extend(arq_u64_bytes(0));
        data.extend(arq_u64_bytes(512)); data.extend(arq_bool_bytes(false)); data.extend(arq_u32_bytes(0));
        let mut cursor = Cursor::new(data);
        let blob_loc = BlobLoc::from_reader(&mut cursor)?;
        assert_eq!(blob_loc.blob_identifier, "blob_id_456"); assert!(!blob_loc.is_packed);
        assert_eq!(blob_loc.relative_path, ""); assert_eq!(blob_loc.length, 512);
        assert!(!blob_loc.stretch_encryption_key); assert_eq!(blob_loc.compression_type, 0);
        Ok(())
    }

    #[test]
    fn test_node_bin_from_reader_file() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_bool_bytes(false)); data.extend(arq_u32_bytes(1));
        data.extend(arq_u64_bytes(1)); data.extend(arq_string_bytes("data_blob_1"));
        data.extend(arq_bool_bytes(true)); data.extend(arq_string_bytes("/pack/data.pack"));
        data.extend(arq_u64_bytes(4096)); data.extend(arq_u64_bytes(100));
        data.extend(arq_bool_bytes(true)); data.extend(arq_u32_bytes(2));
        data.extend(arq_bool_bytes(false)); data.extend(arq_u64_bytes(0));
        data.extend(arq_u64_bytes(100)); data.extend(arq_u64_bytes(0));
        data.extend(arq_i64_bytes(1600000000)); data.extend(arq_i64_bytes(0));
        data.extend(arq_i64_bytes(1600000001)); data.extend(arq_i64_bytes(0));
        data.extend(arq_i64_bytes(1600000002)); data.extend(arq_i64_bytes(0));
        data.extend(arq_string_bytes("user")); data.extend(arq_string_bytes("group"));
        data.extend(arq_bool_bytes(false)); data.extend(arq_i32_bytes(0));
        data.extend(arq_u64_bytes(0)); data.extend(arq_u32_bytes(0o100644));
        data.extend(arq_u32_bytes(1)); data.extend(arq_u32_bytes(501)); data.extend(arq_u32_bytes(20));
        data.extend(arq_i32_bytes(0)); data.extend(arq_i32_bytes(0)); data.extend(arq_u32_bytes(0));
        let mut cursor = Cursor::new(data);
        let node_bin = NodeBin::from_reader(&mut cursor, 1)?;
        assert!(!node_bin.is_tree); assert!(node_bin.tree_blob_loc.is_none());
        assert_eq!(node_bin.data_blob_locs.len(), 1);
        assert_eq!(node_bin.data_blob_locs[0].blob_identifier, "data_blob_1");
        assert_eq!(node_bin.item_size, 100); assert!(node_bin.win_reparse_tag.is_none());
        Ok(())
    }

    #[test]
    fn test_node_bin_from_reader_tree_v2_reparse() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_bool_bytes(true)); data.extend(arq_string_bytes("tree_blob_for_reparse"));
        data.extend(arq_bool_bytes(false)); data.extend(arq_string_empty_bytes());
        data.extend(arq_u64_bytes(0)); data.extend(arq_u64_bytes(0));
        data.extend(arq_bool_bytes(false)); data.extend(arq_u32_bytes(0));
        data.extend(arq_u32_bytes(2)); data.extend(arq_u64_bytes(0));
        data.extend(arq_bool_bytes(false)); data.extend(arq_u64_bytes(0));
        data.extend(arq_u64_bytes(0)); data.extend(arq_u64_bytes(5));
        data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
        data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
        data.extend(arq_i64_bytes(0)); data.extend(arq_i64_bytes(0));
        data.extend(arq_string_empty_bytes()); data.extend(arq_string_empty_bytes());
        data.extend(arq_bool_bytes(false)); data.extend(arq_i32_bytes(0));
        data.extend(arq_u64_bytes(0)); data.extend(arq_u32_bytes(0o040755));
        data.extend(arq_u32_bytes(1)); data.extend(arq_u32_bytes(0)); data.extend(arq_u32_bytes(0));
        data.extend(arq_i32_bytes(0)); data.extend(arq_i32_bytes(0));
        data.extend(arq_u32_bytes(16)); data.extend(arq_u32_bytes(0x80000000u32));
        data.extend(arq_bool_bytes(true));
        let mut cursor = Cursor::new(data);
        let node_bin = NodeBin::from_reader(&mut cursor, 2)?;
        assert!(node_bin.is_tree); assert!(node_bin.tree_blob_loc.is_some());
        assert_eq!(node_bin.win_reparse_tag.unwrap(), 0x80000000u32);
        assert!(node_bin.win_reparse_point_is_directory.unwrap());
        Ok(())
    }

    #[test]
    fn test_tree_bin_from_reader() -> Result<()> {
        let mut data = Vec::new();
        data.extend(arq_u32_bytes(2)); data.extend(arq_u64_bytes(1));
        data.extend(arq_string_bytes("child_file.txt"));
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
        assert!(!child_node.is_tree); assert_eq!(child_node.item_size, 123);
        Ok(())
    }
}

mod arq7_backup_set_tests {
    use super::*;
    use arq::arq7_format::Arq7BackupSet;
    use std::fs::create_dir_all;

    fn create_backup_config_file(path: &std::path::Path, is_encrypted: bool) -> Result<()> {
        let json_content = format!(r#"{{
            "blobIdentifierType": 2, "maxPackedItemLength": 256000, "backupName": "Test Backup Set",
            "isWORM": false, "containsGlacierArchives": false, "additionalUnpackedBlobDirs": [],
            "chunkerVersion": 3, "computerName": "TestComputer", "computerSerial": "unused",
            "blobStorageClass": "STANDARD", "isEncrypted": {}
        }}"#, is_encrypted);
        let mut file = File::create(path.join("backupconfig.json"))?;
        write!(file, "{}", json_content.trim())?;
        Ok(())
    }

    /*
    fn create_dummy_encrypted_keyset_file(path: &std::path::Path) -> Result<()> {
        // ...
    }
    */

    fn create_backup_folders_index_file(path: &std::path::Path) -> Result<()> {
        let json_content = r#"{{
            "standardObjectDirs": ["/TestBackupSet/standardobjects"],
            "standardIAObjectDirs": [], "onezoneIAObjectDirs": [],
            "s3GlacierObjectDirs": [], "s3DeepArchiveObjectDirs": [],
            "importedFrom": null
        }}"#;
        let mut file = File::create(path.join("backupfolders.json"))?;
        write!(file, "{}", json_content.trim())?;
        Ok(())
    }

    fn create_backup_folder_config_file(base_path: &std::path::Path, uuid: &str, name: &str, local_path_str: &str) -> Result<()> {
        let folder_path = base_path.join("backupfolders").join(uuid);
        create_dir_all(&folder_path)?;
        let json_content = format!(r#"{{
            "localPath": "{}", "migratedFromArq60": false, "storageClass": "STANDARD",
            "diskIdentifier": "TEST_DISK", "uuid": "{}", "migratedFromArq5": false,
            "localMountPoint": "/", "name": "{}"
        }}"#, local_path_str, uuid, name);
        let mut file = File::create(folder_path.join("backupfolder.json"))?;
        write!(file, "{}", json_content.trim())?;
        Ok(())
    }

    #[test]
    fn test_arq7_backup_set_load_unencrypted() -> Result<()> {
        let dir = tempdir()?; let base_path = dir.path();
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
        let dir = tempdir()?; let base_path = dir.path();
        create_backup_config_file(base_path, true)?;
        create_backup_folders_index_file(base_path)?;
        let result = Arq7BackupSet::load(base_path, None);
        assert!(result.is_err()); Ok(())
    }

    #[test]
    fn test_list_backup_folder_configs() -> Result<()> {
        let dir = tempdir()?; let base_path = dir.path();
        create_backup_config_file(base_path, false)?;
        create_backup_folders_index_file(base_path)?;
        let uuid1 = "uuid-folder-1"; let uuid2 = "uuid-folder-2";
        create_backup_folder_config_file(base_path, uuid1, "Folder 1", "/docs")?;
        create_backup_folder_config_file(base_path, uuid2, "Folder 2", "/pics")?;
        create_dir_all(base_path.join("backupfolders").join("not-a-folder-config"))?;
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
        let dir = tempdir()?; let base_path = dir.path();
        create_backup_config_file(base_path, false)?;
        create_backup_folders_index_file(base_path)?;
        let backup_set = Arq7BackupSet::load(base_path, None)?;
        let folder_configs = backup_set.list_backup_folder_configs()?;
        assert!(folder_configs.is_empty()); Ok(())
    }
}
/* placeholder for crypto tests */
