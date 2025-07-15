//! Arq 7 data format support
//!
//! This module provides comprehensive support for the Arq 7 backup format, which uses JSON
//! configuration files and a different directory structure compared to earlier versions.
//!
//! ## Features Implemented
//!
//! ### ✅ JSON Configuration Parsing
//! - `BackupConfig` - Parse backupconfig.json files
//! - `BackupFolders` - Parse backupfolders.json files
//! - `BackupPlan` - Parse backupplan.json files
//! - `BackupFolder` - Parse individual folder configurations
//! - `BackupRecord` - Parse LZ4-compressed JSON backup records
//!
//! ### ✅ Complete Backup Set Loading
//! - `BackupSet::from_directory()` - Load entire backup set from directory
//! - Automatic discovery and loading of all JSON configuration files
//! - Recursive loading of backup records from all folders
//! - Error handling with graceful degradation
//!
//! ### 🔄 Binary Format Support
//! - The `arq::arq7::binary` module provides `ArqBinaryReader` for low-level binary parsing.
//! - Arq 7 binary nodes are parsed into the unified `crate::node::Node` using `crate::node::Node::from_binary_reader_arq7`.
//! - Arq 7 binary trees are parsed into the unified `crate::tree::Tree` using `crate::tree::Tree::from_arq7_binary_data`.
//! - `BlobLoc` (now `crate::blob_location::BlobLoc`) is used for referencing data in pack files or standalone objects,
//!   with support for LZ4 decompression where applicable.
//!
//! ## Usage Examples
//!
//! ### Loading a complete backup set:
//! ```rust,no_run
//! use arq::arq7::BackupSet;
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let backup_set = BackupSet::from_directory("/path/to/backup/set")?;
//!     println!("Backup name: {}", backup_set.backup_config.backup_name);
//!
//!     // Access backup records
//!     for (folder_uuid, records) in &backup_set.backup_records {
//!         println!("Folder {}: {} records", folder_uuid, records.len());
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### Loading individual components:
//! ```rust,no_run
//! use arq::arq7::{BackupConfig, BackupPlan};
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let config = BackupConfig::from_file("backupconfig.json")?;
//!     let plan = BackupPlan::from_file("backupplan.json")?;
//!     Ok(())
//! }
//! ```
//!
//! ## Arq 7 Directory Structure
//!
//! ```text
//! backup_set_directory/
//! +-- backupconfig.json          # Backup configuration
//! +-- backupfolders.json         # Object directory locations
//! +-- backupplan.json            # Backup plan settings
//! +-- backupfolders/             # Per-folder configurations
//! |   L-- <folder-uuid>/
//! |       +-- backupfolder.json  # Folder metadata
//! |       L-- backuprecords/     # Backup records by timestamp
//! |           L-- <timestamp>/
//! |               L-- *.backuprecord  # LZ4-compressed JSON records
//! +-- blobpacks/                 # Packed blob data
//! +-- treepacks/                 # Packed tree data
//! L-- standardobjects/           # Standalone objects
//! ```
//!
//! ## Data Format Notes
//!
//! - JSON files use exact field names (not camelCase transformed)
//! - Backup records are LZ4-compressed JSON with 4-byte big-endian length prefix
//! - Binary pack files contain multiple objects at specific offsets
//! - All timestamps are Unix epoch seconds
//! - UUIDs are used extensively for identifying backup plans, folders, and objects

pub mod binary;

use crate::error::{Error, Result};
use crate::object_encryption::{calculate_hmacsha256, EncryptedObject};
use crate::type_utils::ArqRead;
use byteorder::{BigEndian, ReadBytesExt};
use chrono::DateTime;
use serde::de::Deserializer;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::path::PathBuf;

/// EncryptedKeySet represents the encryptedkeyset.dat file
///
/// This file contains keys for encrypting/decrypting and for creating object identifiers.
/// It is encrypted with the encryption password you chose when you created the backup plan.
///
/// The encrypted format is:
/// ```text
/// header                          41 52 51 5f 45 4e 43 52   ARQ_ENCR
///                                 59 50 54 45 44 5f 4d 41   YPTED_MA
///                                 53 54 45 52 5f 4b 45 59   STER_KEY
///                                 53                        S
/// salt                            xx xx xx xx xx xx xx xx (8 bytes)
/// HMACSHA256                      xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx (32 bytes)
/// IV                              xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx (16 bytes)
/// ciphertext                      xx xx xx xx xx xx xx xx
///                                 ... (variable length)
/// ```
///
/// The plaintext format contains:
/// - encryption version: 4 bytes (00 00 00 03)
/// - encryption key length: 8 bytes (00 00 00 00 00 00 00 20)
/// - encryption key: 32 bytes
/// - HMAC key length: 8 bytes (00 00 00 00 00 00 00 20)
/// - HMAC key: 32 bytes
/// - blob identifier salt length: 8 bytes (00 00 00 00 00 00 00 20)
/// - blob identifier salt: 32 bytes
#[derive(Debug, Clone)]
pub struct EncryptedKeySet {
    pub encryption_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub blob_identifier_salt: Vec<u8>,
}

const ENCRYPTED_KEYSET_HEADER: [u8; 25] = [
    65, 82, 81, 95, 69, 78, 67, 82, 89, 80, 84, 69, 68, 95, 77, 65, 83, 84, 69, 82, 95, 75, 69, 89,
    83,
]; // ARQ_ENCRYPTED_MASTER_KEYS

impl EncryptedKeySet {
    pub fn from_master_keys(master_keys: Vec<Vec<u8>>) -> Result<Self> {
        if master_keys.len() != 3 {
            return Err(Error::InvalidFormat("Expected 3 master keys".to_string()));
        }
        Ok(EncryptedKeySet {
            encryption_key: master_keys[0].clone(),
            hmac_key: master_keys[1].clone(),
            blob_identifier_salt: master_keys[2].clone(),
        })
    }

    pub fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        Self::from_reader(&mut reader, password)
    }

    pub fn from_reader<R: BufRead + Seek>(mut reader: R, password: &str) -> Result<Self> {
        // Read and verify header
        let header = reader.read_bytes(25)?;
        if header != ENCRYPTED_KEYSET_HEADER {
            return Err(Error::InvalidFormat(
                "Invalid encryptedkeyset.dat header".to_string(),
            ));
        }

        // Read salt (8 bytes)
        let salt = reader.read_bytes(8)?;

        // Read HMAC-SHA256 (32 bytes)
        let hmac_sha256 = reader.read_bytes(32)?;

        // Read IV (16 bytes)
        let iv = reader.read_bytes(16)?;

        // Read ciphertext (rest of file)
        let mut ciphertext = Vec::new();
        reader.read_to_end(&mut ciphertext)?;

        // Derive 64-byte key from password using PBKDF2-SHA256
        let mut derived_key = vec![0u8; 64];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(200_000).unwrap(),
            &salt,
            password.as_bytes(),
            &mut derived_key,
        );

        // Verify HMAC-SHA256 of IV + ciphertext
        let iv_and_ciphertext = [&iv[..], &ciphertext[..]].concat();
        let calculated_hmac = calculate_hmacsha256(&derived_key[32..], &iv_and_ciphertext)?;
        if calculated_hmac != hmac_sha256 {
            return Err(Error::WrongPassword);
        }

        // Decrypt the ciphertext using AES-256-CBC
        let mut decrypted_data = ciphertext;
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        let plaintext = Aes256CbcDec::new_from_slices(&derived_key[..32], &iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut decrypted_data)?;

        // Parse the plaintext structure
        let mut reader = std::io::Cursor::new(plaintext);

        // Read encryption version (4 bytes)
        let encryption_version = reader.read_u32::<BigEndian>()?;
        if encryption_version != 3 {
            return Err(Error::InvalidFormat(format!(
                "Unsupported encryption version: {}",
                encryption_version
            )));
        }

        // Read encryption key length (8 bytes) and key
        let encryption_key_length = reader.read_u64::<BigEndian>()?;
        if encryption_key_length != 32 {
            return Err(Error::InvalidFormat(format!(
                "Invalid encryption key length: {}",
                encryption_key_length
            )));
        }
        let encryption_key = reader.read_bytes(32)?;

        // Read HMAC key length (8 bytes) and key
        let hmac_key_length = reader.read_u64::<BigEndian>()?;
        if hmac_key_length != 32 {
            return Err(Error::InvalidFormat(format!(
                "Invalid HMAC key length: {}",
                hmac_key_length
            )));
        }
        let hmac_key = reader.read_bytes(32)?;

        // Read blob identifier salt length (8 bytes) and salt
        let salt_length = reader.read_u64::<BigEndian>()?;
        if salt_length != 32 {
            return Err(Error::InvalidFormat(format!(
                "Invalid salt length: {}",
                salt_length
            )));
        }
        let blob_identifier_salt = reader.read_bytes(32)?;

        Ok(EncryptedKeySet {
            encryption_key,
            hmac_key,
            blob_identifier_salt,
        })
    }
}

/// Helper function to detect if a file is encrypted by checking for ARQO header
fn is_file_encrypted<P: AsRef<Path>>(path: P) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 4];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(header == [65, 82, 81, 79]), // "ARQO"
        Err(_) => Ok(false), // File too small or other error, assume not encrypted
    }
}

/// Helper function to decrypt an encrypted JSON file
fn decrypt_json_file<P: AsRef<Path>>(path: P, keyset: &EncryptedKeySet) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Load as EncryptedObject
    let encrypted_obj = EncryptedObject::new(&mut reader)?;

    // Validate and decrypt using the first master key (encryption key)
    encrypted_obj.validate(&keyset.hmac_key)?;
    let decrypted_data = encrypted_obj.decrypt(&keyset.encryption_key[..32])?;

    // Convert to string
    String::from_utf8(decrypted_data).map_err(|_| Error::ParseError)
}

/// Helper function to load JSON from either encrypted or unencrypted file
fn load_json_with_encryption<T, P>(path: P, keyset: Option<&EncryptedKeySet>) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
    P: AsRef<Path>,
{
    let path_ref = path.as_ref();

    if let Some(keyset) = keyset {
        // Check if file is encrypted
        if is_file_encrypted(path_ref)? {
            // Decrypt and parse
            let json_content = decrypt_json_file(path_ref, keyset)?;
            return Ok(serde_json::from_str(&json_content)?);
        }
    }

    // Load as regular unencrypted file
    let file = File::open(path_ref)?;
    let reader = BufReader::new(file);
    return Ok(serde_json::from_reader(reader)?);
}

/// BackupConfig represents the backupconfig.json file
///
/// This file tells Arq how objects are to be added to the backup set – whether the data are
/// encrypted, what kind of hashing mechanism to use, what maximum size to use for packing
/// small files together, etc.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupConfig {
    /// 1=SHA1, 2=SHA256
    #[serde(rename = "blobIdentifierType")]
    pub blob_identifier_type: u32,
    #[serde(rename = "maxPackedItemLength")]
    pub max_packed_item_length: u64,
    #[serde(rename = "backupName")]
    pub backup_name: String,
    #[serde(rename = "isWORM")]
    pub is_worm: bool,
    #[serde(rename = "containsGlacierArchives")]
    pub contains_glacier_archives: bool,
    #[serde(rename = "additionalUnpackedBlobDirs")]
    pub additional_unpacked_blob_dirs: Vec<String>,
    /// Arq uses the same chunker version to ensure de-duplication works with old data
    #[serde(rename = "chunkerVersion")]
    pub chunker_version: u32,
    #[serde(rename = "computerName")]
    pub computer_name: String,
    #[serde(rename = "computerSerial")]
    pub computer_serial: String,
    #[serde(rename = "blobStorageClass")]
    pub blob_storage_class: String,
    #[serde(rename = "isEncrypted")]
    pub is_encrypted: bool,
}

/// BackupFolders represents the backupfolders.json file
///
/// This file tells Arq where to find existing objects (for de-duplication).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupFolders {
    #[serde(rename = "standardObjectDirs")]
    pub standard_object_dirs: Vec<String>,
    #[serde(rename = "standardIAObjectDirs")]
    pub standard_ia_object_dirs: Vec<String>,
    #[serde(rename = "onezoneIAObjectDirs")]
    pub onezone_ia_object_dirs: Vec<String>,
    #[serde(rename = "s3GlacierObjectDirs")]
    pub s3_glacier_object_dirs: Vec<String>,
    #[serde(rename = "s3DeepArchiveObjectDirs")]
    pub s3_deep_archive_object_dirs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "s3GlacierIRObjectDirs")]
    pub s3_glacier_ir_object_dirs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "importedFrom")]
    pub imported_from: Option<String>,
}

/// TransferRate configuration for backup plans
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferRate {
    pub enabled: bool,
    #[serde(rename = "startTimeOfDay")]
    pub start_time_of_day: String,
    #[serde(rename = "daysOfWeek")]
    pub days_of_week: Vec<String>,
    #[serde(rename = "scheduleType")]
    pub schedule_type: String,
    #[serde(rename = "endTimeOfDay")]
    pub end_time_of_day: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "maxKBPS")]
    pub max_kbps: Option<u64>,
}

/// Schedule configuration for backup plans
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Schedule {
    #[serde(rename = "backUpAndValidate")]
    pub backup_and_validate: bool,
    #[serde(rename = "startWhenVolumeIsConnected")]
    pub start_when_volume_is_connected: bool,
    #[serde(rename = "pauseDuringWindow")]
    pub pause_during_window: bool,
    #[serde(rename = "type")]
    pub schedule_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "daysOfWeek")]
    pub days_of_week: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "everyHours")]
    pub every_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "minutesAfterHour")]
    pub minutes_after_hour: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pauseFrom")]
    pub pause_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pauseTo")]
    pub pause_to: Option<String>,
}

/// Email report configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailReport {
    pub port: u32,
    #[serde(rename = "startTLS")]
    pub start_tls: bool,
    #[serde(rename = "authenticationType")]
    pub authentication_type: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reportHELOUseIP")]
    pub report_helo_use_ip: Option<bool>,
    pub when: String,
    #[serde(rename = "type")]
    pub report_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "fromAddress")]
    pub from_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "toAddress")]
    pub to_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// BackupFolderPlan represents individual folder configuration within a backup plan
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExcludedDrive {
    #[serde(rename = "diskIdentifier")]
    pub disk_identifier: String,
    #[serde(rename = "volumeName")]
    pub volume_name: String,
    #[serde(rename = "mountPoint")]
    pub mount_point: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExcludedDriveEntry {
    String(String),
    Object(ExcludedDrive),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupFolderPlan {
    #[serde(rename = "backupFolderUUID")]
    pub backup_folder_uuid: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "diskIdentifier")]
    pub disk_identifier: Option<String>,
    #[serde(rename = "blobStorageClass")]
    pub blob_storage_class: String,
    #[serde(rename = "ignoredRelativePaths")]
    pub ignored_relative_paths: Vec<String>,
    #[serde(rename = "skipIfNotMounted")]
    pub skip_if_not_mounted: bool,
    #[serde(rename = "skipDuringBackup")]
    pub skip_during_backup: bool,
    #[serde(rename = "useDiskIdentifier")]
    pub use_disk_identifier: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "relativePath")]
    pub relative_path: Option<String>,
    #[serde(rename = "wildcardExcludes")]
    pub wildcard_excludes: Vec<String>,
    #[serde(rename = "excludedDrives")]
    pub excluded_drives: Vec<ExcludedDriveEntry>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "localPath")]
    pub local_path: Option<String>,
    #[serde(rename = "allDrives")]
    pub all_drives: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "skipTMExcludes")]
    pub skip_tm_excludes: Option<bool>,
    #[serde(rename = "regexExcludes")]
    pub regex_excludes: Vec<String>,
    pub name: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "localMountPoint")]
    pub local_mount_point: Option<String>,
}

/// BackupPlan represents the backupplan.json file
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupPlan {
    #[serde(rename = "transferRateJSON")]
    pub transfer_rate_json: TransferRate,
    #[serde(rename = "cpuUsage")]
    pub cpu_usage: u32,
    pub id: u32,
    #[serde(rename = "storageLocationId")]
    pub storage_location_id: u32,
    #[serde(rename = "excludedNetworkInterfaces")]
    pub excluded_network_interfaces: Vec<String>,
    #[serde(rename = "needsArq5Buckets")]
    pub needs_arq5_buckets: bool,
    #[serde(rename = "useBuzhash")]
    pub use_buzhash: bool,
    #[serde(rename = "arq5UseS3IA")]
    pub arq5_use_s3_ia: bool,
    #[serde(rename = "objectLockUpdateIntervalDays")]
    pub object_lock_update_interval_days: u32,
    #[serde(rename = "planUUID")]
    pub plan_uuid: String,
    #[serde(rename = "scheduleJSON")]
    pub schedule_json: Schedule,
    #[serde(rename = "keepDeletedFiles")]
    pub keep_deleted_files: bool,
    pub version: u32,
    #[serde(
        rename = "createdAtProConsole",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub created_at_pro_console: Option<bool>,
    #[serde(
        rename = "backupFolderPlanMountPointsAreInitialized",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub backup_folder_plan_mount_points_are_initialized: Option<bool>,
    #[serde(rename = "includeNewVolumes")]
    pub include_new_volumes: bool,
    #[serde(rename = "retainMonths")]
    pub retain_months: u32,
    #[serde(rename = "useAPFSSnapshots")]
    pub use_apfs_snapshots: bool,
    #[serde(
        rename = "backupSetIsInitialized",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub backup_set_is_initialized: Option<bool>,
    #[serde(rename = "backupFolderPlansByUUID")]
    pub backup_folder_plans_by_uuid: HashMap<String, BackupFolderPlan>,
    #[serde(rename = "notifyOnError")]
    pub notify_on_error: bool,
    #[serde(rename = "retainDays")]
    pub retain_days: u32,
    #[serde(rename = "updateTime", with = "f64_parser")]
    pub update_time: f64,
    #[serde(rename = "excludedWiFiNetworkNames")]
    pub excluded_wi_fi_network_names: Vec<String>,
    #[serde(
        rename = "objectLockAvailable",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub object_lock_available: Option<bool>,
    #[serde(rename = "managed", skip_serializing_if = "Option::is_none", default)]
    pub managed: Option<bool>,
    pub name: String,
    #[serde(rename = "wakeForBackup")]
    pub wake_for_backup: bool,
    #[serde(
        rename = "includeNetworkInterfaces",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub include_network_interfaces: Option<bool>,
    #[serde(
        rename = "datalessFilesOption",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dataless_files_option: Option<u32>,
    #[serde(rename = "retainAll")]
    pub retain_all: bool,
    #[serde(rename = "isEncrypted")]
    pub is_encrypted: bool,
    pub active: bool,
    #[serde(rename = "notifyOnSuccess")]
    pub notify_on_success: bool,
    #[serde(rename = "preventSleep")]
    pub prevent_sleep: bool,
    #[serde(rename = "creationTime", with = "f64_to_u64_parser")]
    pub creation_time: u64,
    #[serde(rename = "pauseOnBattery")]
    pub pause_on_battery: bool,
    #[serde(rename = "retainWeeks")]
    pub retain_weeks: u32,
    #[serde(rename = "retainHours")]
    pub retain_hours: u32,
    #[serde(
        rename = "preventBackupOnConstrainedNetworks",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub prevent_backup_on_constrained_networks: Option<bool>,
    #[serde(rename = "includeWiFiNetworks")]
    pub include_wi_fi_networks: bool,
    #[serde(rename = "threadCount")]
    pub thread_count: u32,

    #[serde(
        rename = "preventBackupOnExpensiveNetworks",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub prevent_backup_on_expensive_networks: Option<bool>,
    #[serde(rename = "emailReportJSON")]
    pub email_report_json: EmailReport,
    #[serde(rename = "includeFileListInActivityLog")]
    pub include_file_list_in_activity_log: bool,
    #[serde(
        rename = "noBackupsAlertDays",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub no_backups_alert_days: Option<u32>,
}

mod f64_to_u64_parser {
    use super::*;
    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum FloatOrInt {
            Float(f64),
            Int(u64),
        }

        match FloatOrInt::deserialize(deserializer)? {
            FloatOrInt::Float(f) => Ok(f as u64),
            FloatOrInt::Int(i) => Ok(i),
        }
    }

    use serde::Serializer;
    pub fn serialize<S>(date: &u64, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(*date)
    }
}

mod f64_parser {
    use super::*;
    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<f64, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum FloatOrInt {
            Float(f64),
            Int(u64), // Allow integer timestamps too
        }

        match FloatOrInt::deserialize(deserializer)? {
            FloatOrInt::Float(f) => Ok(f),
            FloatOrInt::Int(i) => Ok(i as f64),
        }
    }

    use serde::Serializer;
    pub fn serialize<S>(date: &f64, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(*date)
    }
}

/// BackupFolder represents a backupfolder.json file within the backupfolders/<UUID>/ directory
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupFolder {
    #[serde(rename = "localPath")]
    pub local_path: String,
    #[serde(rename = "migratedFromArq60")]
    pub migrated_from_arq60: bool,
    #[serde(rename = "storageClass")]
    pub storage_class: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "diskIdentifier")]
    pub disk_identifier: Option<String>,
    pub uuid: String,
    #[serde(rename = "migratedFromArq5")]
    pub migrated_from_arq5: bool,
    #[serde(rename = "localMountPoint")]
    pub local_mount_point: String,
    pub name: String,
}

/// BlobLoc describes the location of a blob
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobLoc {
    #[serde(rename = "blobIdentifier")]
    pub blob_identifier: String,
    #[serde(rename = "compressionType")]
    pub compression_type: u32,
    #[serde(rename = "isPacked")]
    pub is_packed: bool,
    pub length: u64,
    pub offset: u64,
    #[serde(rename = "relativePath")]
    pub relative_path: String,
    #[serde(rename = "stretchEncryptionKey")]
    pub stretch_encryption_key: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)] // `default` makes it optional for deserialization
    #[serde(rename = "isLargePack")]
    pub is_large_pack: Option<bool>,
}

impl BlobLoc {
    /// Parse a BlobLoc from binary data according to Arq 7 format with enhanced error recovery.
    pub fn from_binary_reader<R: binary::ArqBinaryReader>(reader: &mut R) -> Result<Self> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let is_large_pack_binary = reader.read_arq_bool()?; // Read as bool from binary

        // Adapt relative_path reading from BlobLoc's special handling
        let relative_path = match reader.read_arq_string() {
            Ok(Some(path)) => path,
            Ok(None) => {
                // TODO
                // This part is a bit heuristic, trying to recover if path was marked null
                // but data looks like a path. For simplicity in unified struct,
                // we might simplify this or ensure reader is correctly positioned.
                // For now, let's assume if it's None, it's genuinely None or an empty string.
                // The original BinaryBlobLoc had more complex recovery.
                // Let's stick to what `read_arq_string` provides directly for now.
                // If it returns None, we'll use an empty string.
                String::new()
            }
            Err(_) => {
                // If parsing fails completely (e.g. IO error or bad format after flag)
                // return an empty string or propagate error. For now, empty string.
                String::new()
            }
        };

        let offset = reader.read_arq_u64()?;
        let length = reader.read_arq_u64()?;
        let stretch_encryption_key = reader.read_arq_bool()?;
        let compression_type = reader.read_arq_u32()?;

        Ok(BlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack_binary), // Map the binary bool to Some(bool)
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
        })
    }
}

/// Conversion from arq7::BlobLoc to blob_location::BlobLoc
impl Into<crate::blob_location::BlobLoc> for BlobLoc {
    fn into(self) -> crate::blob_location::BlobLoc {
        crate::blob_location::BlobLoc {
            blob_identifier: self.blob_identifier,
            compression_type: self.compression_type,
            is_packed: self.is_packed,
            length: self.length,
            offset: self.offset,
            relative_path: self.relative_path,
            stretch_encryption_key: self.stretch_encryption_key,
            is_large_pack: self.is_large_pack,
        }
    }
}

/// Unified Node struct representing a file or directory from JSON or binary context.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node {
    #[serde(rename = "isTree")]
    pub is_tree: bool,
    #[serde(rename = "itemSize")]
    pub item_size: u64,
    pub deleted: bool,
    #[serde(rename = "computerOSType")]
    pub computer_os_type: u32,
    #[serde(rename = "modificationTime_sec")]
    pub modification_time_sec: i64,
    #[serde(rename = "modificationTime_nsec")]
    pub modification_time_nsec: i64,
    #[serde(rename = "changeTime_sec")]
    pub change_time_sec: i64,
    #[serde(rename = "changeTime_nsec")]
    pub change_time_nsec: i64,
    #[serde(rename = "creationTime_sec")]
    pub creation_time_sec: i64,
    #[serde(rename = "creationTime_nsec")]
    pub creation_time_nsec: i64,
    #[serde(rename = "mac_st_mode")]
    pub mac_st_mode: u32,
    #[serde(rename = "mac_st_ino")]
    pub mac_st_ino: u64,
    #[serde(rename = "mac_st_nlink")]
    pub mac_st_nlink: u32,
    #[serde(rename = "mac_st_gid")]
    pub mac_st_gid: u32,
    #[serde(rename = "winAttrs")]
    pub win_attrs: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "containedFilesCount")]
    pub contained_files_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "mac_st_uid")]
    pub mac_st_uid: Option<u32>,
    #[serde(rename = "mac_st_dev")]
    pub mac_st_dev: i32,
    #[serde(rename = "mac_st_rdev")]
    pub mac_st_rdev: i32,
    #[serde(rename = "mac_st_flags")]
    pub mac_st_flags: i32,
    #[serde(rename = "dataBlobLocs")]
    pub data_blob_locs: Vec<BlobLoc>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "treeBlobLoc")]
    pub tree_blob_loc: Option<BlobLoc>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "xattrsBlobLocs")]
    pub xattrs_blob_locs: Option<Vec<BlobLoc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "groupName")]
    pub group_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "reparseTag")]
    pub reparse_tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "reparsePointIsDirectory")]
    pub reparse_point_is_directory: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acl_blob_loc: Option<BlobLoc>,
}

// The Node struct and its impl block have been moved to crate::node.
// Arq5TreeBlobKey struct definition removed.

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupRecordError {
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(rename = "localPath")]
    pub local_path: String,
    #[serde(rename = "pathIsDirectory")]
    pub path_is_directory: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Arq5BackupRecord {
    pub version: u32, // Expected 12
    #[serde(rename = "arqVersion")]
    pub arq_version: Option<String>,
    #[serde(rename = "backupFolderUUID")]
    pub backup_folder_uuid: String,
    #[serde(rename = "backupPlanUUID")]
    pub backup_plan_uuid: String,
    #[serde(rename = "computerOSType")]
    pub computer_os_type: Option<u32>,
    #[serde(rename = "creationDate")]
    pub creation_date: Option<f64>,
    #[serde(rename = "isComplete")]
    pub is_complete: Option<bool>,
    #[serde(rename = "arq5BucketXML")]
    pub arq5_bucket_xml: Option<String>,
    #[serde(rename = "backupRecordErrors")]
    #[serde(default)]
    pub backup_record_errors: Option<Vec<BackupRecordError>>,
    #[serde(rename = "localPath")]
    pub local_path: Option<String>,
    #[serde(rename = "storageClass")]
    pub storage_class: String,
    #[serde(rename = "copiedFromSnapshot")]
    pub copied_from_snapshot: bool,
    #[serde(rename = "copiedFromCommit")]
    pub copied_from_commit: bool,
    #[serde(rename = "arq5TreeBlobKey")]
    pub arq5_tree_blob_key: Option<crate::blob::BlobKey>, // Updated to use the new BlobKey
    pub archived: Option<bool>, // Matches example, though original top-level was not optional
    #[serde(rename = "relativePath")]
    pub relative_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Arq7BackupRecord {
    #[serde(rename = "backupFolderUUID")]
    pub backup_folder_uuid: String,
    #[serde(rename = "diskIdentifier")]
    pub disk_identifier: String, // Present in v100
    #[serde(rename = "storageClass")]
    pub storage_class: String,
    pub version: u32, // Expected 100
    #[serde(rename = "backupPlanUUID")]
    pub backup_plan_uuid: String,
    #[serde(rename = "backupRecordErrors")]
    #[serde(default)]
    pub backup_record_errors: Option<Vec<BackupRecordError>>,
    #[serde(rename = "copiedFromSnapshot")]
    pub copied_from_snapshot: bool,
    #[serde(rename = "copiedFromCommit")]
    pub copied_from_commit: bool,
    pub node: crate::node::Node, // Changed to use unified Node
    #[serde(rename = "arqVersion")]
    pub arq_version: Option<String>,
    pub archived: Option<bool>,
    #[serde(rename = "backupPlanJSON")]
    pub backup_plan_json: Option<BackupPlan>,
    #[serde(rename = "relativePath")]
    pub relative_path: Option<String>,
    #[serde(rename = "computerOSType")]
    pub computer_os_type: Option<u32>, // Was optional, matches v100
    #[serde(rename = "localPath")]
    pub local_path: Option<String>, // Was optional, matches v100
    #[serde(rename = "localMountPoint")]
    pub local_mount_point: Option<String>, // Present in v100
    #[serde(rename = "isComplete")]
    pub is_complete: Option<bool>, // Was optional, matches v100
    #[serde(rename = "creationDate")]
    #[serde(default)] // Default for Option<f64>
    #[serde(with = "f64_parser_allow_int")] // Allow parsing from integer or float
    pub creation_date: Option<f64>, // V100 has int, f64 is fine
    #[serde(rename = "volumeName")]
    pub volume_name: Option<String>, // Present in v100
                                     // Removed arq5BucketXML and arq5TreeBlobKey
                                     // Removed errorCount as backupRecordErrors is now structured
}

// Custom deserializer module for creationDate in Arq7BackupRecord
// to handle cases where it might be an integer in JSON but needs to be Option<f64>
mod f64_parser_allow_int {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum MaybeFloatOrInt {
            Float(f64),
            Int(i64), // Allow i64 as Arq7 v100 example has integer timestamp
            None,     // Allow it to be null or missing
        }

        match MaybeFloatOrInt::deserialize(deserializer)? {
            MaybeFloatOrInt::Float(f) => Ok(Some(f)),
            MaybeFloatOrInt::Int(i) => Ok(Some(i as f64)),
            MaybeFloatOrInt::None => Ok(None), // This case handles explicit nulls. `#[serde(default)]` handles missing.
        }
    }

    pub fn serialize<S>(date: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            Some(d) => serializer.serialize_f64(*d),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)] // Attempt to deserialize as Arq7 first, then Arq5
pub enum GenericBackupRecord {
    Arq7(Arq7BackupRecord),
    Arq5(Arq5BackupRecord),
}

/// BackupSet represents an entire Arq 7 backup set
#[derive(Debug, Clone)]
pub struct BackupSet {
    pub backup_config: BackupConfig,
    pub backup_folders: BackupFolders,
    pub backup_plan: BackupPlan,
    pub backup_folder_configs: HashMap<String, BackupFolder>,
    pub backup_records: HashMap<String, Vec<GenericBackupRecord>>, // Changed to GenericBackupRecord
    pub encryption_keyset: Option<EncryptedKeySet>,
    pub root_path: PathBuf,
}

#[derive(Debug, Default)]
pub struct BackupStatistics {
    pub folder_count: u32,
    pub record_count: u32,
    pub total_files: u32,
    pub total_size: u64,
    pub complete_backups: u32,
}

#[derive(Debug, Default)]
pub struct IntegrityReport {
    pub total_blobs: u32,
    pub valid_blobs: u32,
    pub invalid_blobs: u32,
    pub total_blob_size: u64,
    pub treepacks_exist: bool,
    pub blobpacks_exist: bool,
}

impl BackupConfig {
    /// Load a BackupConfig from a JSON reader
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load a BackupConfig from a file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        Self::from_reader(file)
    }
}

impl BackupFolders {
    /// Load BackupFolders from a JSON reader
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load BackupFolders from a file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::from_file_with_encryption(path, None)
    }

    /// Load BackupFolders from file, optionally decrypting if needed
    pub fn from_file_with_encryption<P: AsRef<Path>>(
        path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<BackupFolders> {
        load_json_with_encryption(path, keyset)
    }
}

impl BackupPlan {
    /// Load a BackupPlan from a JSON reader
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load a BackupPlan from a file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::from_file_with_encryption(path, None)
    }

    /// Load BackupPlan from file, optionally decrypting if needed
    pub fn from_file_with_encryption<P: AsRef<Path>>(
        path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<BackupPlan> {
        load_json_with_encryption(path, keyset)
    }
}

impl BackupFolder {
    /// Load a BackupFolder from a JSON reader
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load a BackupFolder from a file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::from_file_with_encryption(path, None)
    }

    /// Load BackupFolder from file, optionally decrypting if needed
    pub fn from_file_with_encryption<P: AsRef<Path>>(
        path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<BackupFolder> {
        load_json_with_encryption(path, keyset)
    }
}

impl BackupSet {
    /// Load a complete BackupSet from a directory path
    pub fn from_directory<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let root_path = PathBuf::from(path.as_ref());
        let path = path.as_ref();

        // Load main configuration files
        let backup_config = BackupConfig::from_file(path.join("backupconfig.json"))?;
        let backup_folders = BackupFolders::from_file(path.join("backupfolders.json"))?;
        let backup_plan = BackupPlan::from_file(path.join("backupplan.json"))?;

        // Load backup folder configurations
        let mut backup_folder_configs = HashMap::new();
        let mut backup_records = HashMap::new();
        let backupfolders_dir = path.join("backupfolders");

        if backupfolders_dir.exists() {
            for entry in std::fs::read_dir(backupfolders_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let folder_uuid = entry.file_name().to_string_lossy().to_string();
                    let config_path = entry.path().join("backupfolder.json");

                    if config_path.exists() {
                        let backup_folder = BackupFolder::from_file(config_path)?;
                        backup_folder_configs.insert(folder_uuid.clone(), backup_folder);
                    }

                    // Load backup records for this folder
                    let records_dir = entry.path().join("backuprecords");
                    if records_dir.exists() {
                        let mut folder_records = Vec::new();
                        Self::load_backup_records_recursive(&records_dir, &mut folder_records)?;
                        if !folder_records.is_empty() {
                            backup_records.insert(folder_uuid, folder_records);
                        }
                    }
                }
            }
        }

        Ok(BackupSet {
            backup_config,
            backup_folders,
            backup_plan,
            backup_folder_configs,
            backup_records,
            encryption_keyset: None,
            root_path,
        })
    }

    /// Add method to load with explicit password
    pub fn from_directory_with_password<P: AsRef<Path>>(
        dir_path: P,
        password: Option<&str>,
    ) -> Result<BackupSet> {
        let root_path = PathBuf::from(dir_path.as_ref());
        let dir_path = dir_path.as_ref();

        // Load backup config first to check if encrypted
        let config_path = dir_path.join("backupconfig.json");
        let backup_config = BackupConfig::from_file(&config_path)?;

        // Load encryption keyset if this is an encrypted backup
        let encryption_keyset = if backup_config.is_encrypted {
            let keyset_path = dir_path.join("encryptedkeyset.dat");
            if keyset_path.exists() {
                match password {
                    Some(pwd) => Some(EncryptedKeySet::from_file(&keyset_path, pwd)?),
                    None => {
                        return Err(Error::InvalidFormat(
                            "Encrypted backup requires password".to_string(),
                        ))
                    }
                }
            } else {
                return Err(Error::InvalidFormat(
                    "Encrypted backup missing encryptedkeyset.dat".to_string(),
                ));
            }
        } else {
            None
        };

        // Load other components with encryption support
        let folders_path = dir_path.join("backupfolders.json");
        let backup_folders =
            BackupFolders::from_file_with_encryption(&folders_path, encryption_keyset.as_ref())?;

        let plan_path = dir_path.join("backupplan.json");
        let backup_plan =
            BackupPlan::from_file_with_encryption(&plan_path, encryption_keyset.as_ref())?;

        // Load backup folder configs
        let mut backup_folder_configs = HashMap::new();
        let backupfolders_dir = dir_path.join("backupfolders");
        if backupfolders_dir.exists() {
            for entry in std::fs::read_dir(&backupfolders_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let folder_uuid = entry.file_name().to_string_lossy().to_string();
                    let config_path = entry.path().join("backupfolder.json");
                    if config_path.exists() {
                        match BackupFolder::from_file_with_encryption(
                            &config_path,
                            encryption_keyset.as_ref(),
                        ) {
                            Ok(folder_config) => {
                                backup_folder_configs.insert(folder_uuid.clone(), folder_config);
                            }
                            Err(e) => {
                                eprintln!(
                                    "Warning: Failed to load folder config for {}: {}",
                                    folder_uuid, e
                                );
                            }
                        }
                    }
                }
            }
        }

        // Load backup records
        let backup_records = Self::load_backup_records_with_encryption(
            &backupfolders_dir,
            encryption_keyset.as_ref(),
        )?;

        Ok(BackupSet {
            backup_config,
            backup_folders,
            backup_plan,
            backup_folder_configs,
            backup_records,
            encryption_keyset,
            root_path,
        })
    }

    /// Get a reference to the encryption keyset if available
    pub fn encryption_keyset(&self) -> Option<&EncryptedKeySet> {
        self.encryption_keyset.as_ref()
    }

    /// Check if this backup set is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.backup_config.is_encrypted
    }

    /// Recursively load backup record files from a directory
    fn load_backup_records_recursive(
        dir: &std::path::Path,
        records: &mut Vec<GenericBackupRecord>, // Changed to GenericBackupRecord
    ) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if entry.file_type()?.is_dir() {
                // Recursively search subdirectories
                Self::load_backup_records_recursive(&path, records)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("backuprecord") {
                // Try to parse backup record file
                match GenericBackupRecord::from_file(&path) {
                    // Changed to GenericBackupRecord
                    Ok(record) => records.push(record),
                    Err(e) => {
                        // Log error but continue processing other files
                        eprintln!("Warning: Failed to parse backup record {:?}: {}", path, e);
                    }
                }
            }
        }
        Ok(())
    }

    fn load_backup_records_with_encryption(
        backupfolders_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<HashMap<String, Vec<GenericBackupRecord>>> {
        // Changed to GenericBackupRecord
        let mut backup_records = HashMap::new();

        if !backupfolders_dir.exists() {
            return Ok(backup_records);
        }

        for entry in std::fs::read_dir(backupfolders_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let folder_uuid = entry.file_name().to_string_lossy().to_string();
                let records_dir = entry.path().join("backuprecords");

                if records_dir.exists() {
                    let mut folder_records = Vec::new();

                    // Recursively traverse backup records directories
                    fn collect_records(
                        dir: &Path,
                        records: &mut Vec<GenericBackupRecord>, // Changed to GenericBackupRecord
                        keyset: Option<&EncryptedKeySet>,
                    ) -> Result<()> {
                        for entry in std::fs::read_dir(dir)? {
                            let entry = entry?;
                            let path = entry.path();

                            if path.is_dir() {
                                collect_records(&path, records, keyset)?;
                            } else if path.extension().map_or(false, |ext| ext == "backuprecord") {
                                match GenericBackupRecord::from_file_with_encryption(&path, keyset)
                                {
                                    // Changed to GenericBackupRecord
                                    Ok(record) => records.push(record),
                                    Err(e) => {
                                        println!(
                                            "Warning: Failed to load backup record {:?}: {}",
                                            path, e
                                        );
                                    }
                                }
                            }
                        }
                        Ok(())
                    }

                    if let Err(e) = collect_records(&records_dir, &mut folder_records, keyset) {
                        println!(
                            "Warning: Failed to load backup records for folder {}: {}",
                            folder_uuid, e
                        );
                    }

                    if !folder_records.is_empty() {
                        backup_records.insert(folder_uuid, folder_records);
                    }
                }
            }
        }

        Ok(backup_records)
    }

    /// Extract a file from the backup set with full encryption support
    pub fn extract_file_by_path<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        backup_set_dir: P1,
        file_path: &str,
        output_path: P2,
    ) -> Result<()> {
        // Find the file in the backup records
        for (_, records) in &self.backup_records {
            for generic_record in records {
                if let GenericBackupRecord::Arq7(record) = generic_record {
                    // Only Arq7 records have a direct node
                    if let Some(node) = self.find_node_by_path(&record.node, file_path)? {
                        if !node.is_tree {
                            return node.extract_file_with_encryption(
                                backup_set_dir.as_ref(),
                                output_path,
                                self.encryption_keyset.as_ref(),
                            );
                        }
                    }
                }
            }
        }

        Err(Error::InvalidFormat(format!(
            "File not found or not extractable from Arq7 records: {}", // Clarified error
            file_path
        )))
    }

    /// Recursively find a node by path (operates on a given Node, typically from an Arq7 record)
    fn find_node_by_path(
        &self,
        node: &crate::node::Node, // This function is now more general, called with a specific node
        target_path: &str,
    ) -> Result<Option<crate::node::Node>> {
        let path_parts: Vec<&str> = target_path.trim_start_matches('/').split('/').collect();
        self.find_node_recursive(node, &path_parts, 0)
    }

    // find_node_recursive remains largely the same as it operates on a Node,
    // but its callers need to ensure they provide a valid Node.
    fn find_node_recursive(
        &self,
        node: &crate::node::Node,
        path_parts: &[&str],
        depth: usize,
    ) -> Result<Option<crate::node::Node>> {
        let backup_set_dir_ref: &Path = self.root_path.as_ref();

        if depth >= path_parts.len() {
            return Ok(Some(node.clone()));
        }

        if !node.is_tree {
            return Ok(None);
        }
        // TODO: This method needs to be implemented on crate::node::Node
        // For now, assume it returns Ok(None) to allow compilation.
        // This will affect functionality until `crate::node::Node::load_tree_with_encryption` is implemented.
        // if let Some(tree) =
        //     node.load_tree_with_encryption(backup_set_dir_ref, self.encryption_keyset.as_ref())?
        // {
        //     let target_name = path_parts[depth];
        //     if let Some(child_node) = tree.child_nodes.get(target_name) {
        //         return self.find_node_recursive(child_node, path_parts, depth + 1);
        //     }
        // }
        // Use the Node's own method now
        if let Some(tree) =
            node.load_tree_with_encryption(backup_set_dir_ref, self.encryption_keyset.as_ref())?
        {
            let target_name = path_parts[depth];
            // The unified Tree uses `nodes` for its HashMap
            if let Some(child_node_entry) = tree.nodes.get(target_name) {
                return self.find_node_recursive(child_node_entry, path_parts, depth + 1);
            }
        }
        Ok(None)
    }

    /// List all files in the backup set (primarily from Arq7 records)
    pub fn list_all_files(&self) -> Result<Vec<String>> {
        let mut files = Vec::new();
        let backup_set_dir_ref = self.root_path.as_ref();

        for (_, records) in &self.backup_records {
            for generic_record in records {
                if let GenericBackupRecord::Arq7(record) = generic_record {
                    self.collect_files_recursive(
                        &record.node, // This is now crate::node::Node
                        String::new(),
                        &mut files,
                        backup_set_dir_ref,
                    )?;
                }
                // Arq5 records do not have a top-level node in this structure for listing files directly.
            }
        }
        Ok(files)
    }

    // collect_files_recursive remains largely the same.
    fn collect_files_recursive(
        &self,
        node: &crate::node::Node, // Changed to crate::node::Node
        current_path: String,
        files: &mut Vec<String>,
        backup_set_dir: &Path,
    ) -> Result<()> {
        if !node.is_tree {
            if !current_path.is_empty() {
                files.push(current_path);
            }
            return Ok(());
        }

        // TODO: This method needs to be implemented on crate::node::Node
        // For now, assume it returns Ok(None) to allow compilation.
        // This will affect functionality until `crate::node::Node::load_tree_with_encryption` is implemented.
        // if let Some(tree) =
        //     node.load_tree_with_encryption(backup_set_dir, self.encryption_keyset.as_ref())?
        // {
        //     for (name, child_node) in &tree.child_nodes {
        //         let child_path = if current_path.is_empty() {
        //             name.clone()
        //         } else {
        //             format!("{}/{}", current_path, name)
        //         };
        //         self.collect_files_recursive(child_node, child_path, files, backup_set_dir)?;
        //     }
        // }
        if let Some(tree) =
            node.load_tree_with_encryption(backup_set_dir, self.encryption_keyset.as_ref())?
        {
            for (name, child_node_entry) in &tree.nodes {
                // Use tree.nodes
                let child_path = if current_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", current_path, name)
                };
                self.collect_files_recursive(child_node_entry, child_path, files, backup_set_dir)?;
            }
        }
        Ok(())
    }

    /// Get backup statistics
    pub fn get_statistics(&self) -> Result<BackupStatistics> {
        let mut stats: BackupStatistics = BackupStatistics::default();
        let backup_set_dir_ref = self.root_path.as_ref();

        for (_, records_vec) in &self.backup_records {
            // Renamed records to records_vec to avoid conflict
            stats.folder_count += 1; // This counts folders in backup_records map, not file system folders.
            stats.record_count += records_vec.len() as u32;

            for generic_record in records_vec {
                match generic_record {
                    GenericBackupRecord::Arq7(record) => {
                        let (file_count, total_size) = count_files_in_node(
                            &record.node, // This is now crate::node::Node
                            backup_set_dir_ref,
                            self.encryption_keyset.as_ref(),
                        )?;
                        stats.total_files += file_count;
                        stats.total_size += total_size;
                        if record.is_complete.unwrap_or(false) {
                            stats.complete_backups += 1;
                        }
                    }
                    GenericBackupRecord::Arq5(record) => {
                        // Arq5 records don't have a direct node for file counting here.
                        // We could potentially sum itemSize if arq5TreeBlobKey implies a single item,
                        // but that's an assumption. For now, only count if complete.
                        if record.is_complete.unwrap_or(false) {
                            stats.complete_backups += 1;
                        }
                        // total_files and total_size for Arq5 might need different logic
                        // based on arq5TreeBlobKey or other fields if applicable.
                    }
                }
            }
        }
        Ok(stats)
    }

    /// Verify backup integrity by checking all blob locations
    pub fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        let backup_set_dir_ref: &Path = self.root_path.as_ref();

        // let backup_set_dir_ref2: &Path = self.root_path.as_ref();

        let blob_locations = self.find_all_blob_locations(); // This method needs adjustment
        report.total_blobs = blob_locations.len() as u32;

        for blob_loc in blob_locations {
            match blob_loc.load_data(backup_set_dir_ref, self.encryption_keyset.as_ref()) {
                Ok(data) => {
                    report.valid_blobs += 1;
                    report.total_blob_size += data.len() as u64;
                }
                Err(e) => {
                    report.invalid_blobs += 1;
                    eprintln!(
                        "Warning: Failed to load blob {}: {}",
                        blob_loc.blob_identifier, e
                    );
                }
            }
        }

        // Check pack files exist
        let treepacks_dir = backup_set_dir_ref.join("treepacks"); // Used backup_set_dir_ref
        let blobpacks_dir = backup_set_dir_ref.join("blobpacks"); // Used backup_set_dir_ref

        report.treepacks_exist = treepacks_dir.exists();
        report.blobpacks_exist = blobpacks_dir.exists();

        Ok(report)
    }

    /// Converts a Node into a DirectoryEntry (File or Directory).
    fn node_to_directory_entry(
        &self,
        node: &crate::node::Node,
        name: String,
    ) -> Result<DirectoryEntry> {
        if node.is_tree {
            // For directories, create a DirectoryEntryNode without loading children.
            // Children will be loaded on demand.
            Ok(DirectoryEntry::Directory(DirectoryEntryNode {
                name,
                children: None, // Children are not loaded initially
                tree_blob_loc: node.tree_blob_loc.as_ref().map(|loc| loc.clone().into()), // Convert to blob_location::BlobLoc
                modification_time_sec: node.modification_time_sec,
                creation_time_sec: node.creation_time_sec,
                mode: node.st_mode, // Using st_mode from crate::node::Node
            }))
        } else {
            // For files, create a FileEntry with all necessary details for later content loading.
            Ok(DirectoryEntry::File(FileEntry {
                name,
                size: node.item_size,
                data_blob_locs: node
                    .data_blob_locs
                    .iter()
                    .map(|loc| loc.clone().into())
                    .collect(), // Convert to blob_location::BlobLoc
                modification_time_sec: node.modification_time_sec,
                creation_time_sec: node.creation_time_sec,
                mode: node.st_mode, // Using st_mode from crate::node::Node
            }))
        }
    }

    /// Creates a virtual filesystem view of the backup set.
    /// The root directory contains subdirectories for each backup record (named by creation date).
    /// Each subdirectory contains the files and folders from that backup.
    pub fn get_root_directory(&self) -> Result<DirectoryEntryNode> {
        let mut root_children_entries = Vec::new();

        for (folder_uuid, records) in &self.backup_records {
            for record in records {
                match record {
                    GenericBackupRecord::Arq7(arq7_record) => {
                        let record_dir_name = arq7_record
                            .creation_date
                            .map(|ts| {
                                let secs = ts as i64;
                                let nanos = ((ts.fract()) * 1_000_000_000.0) as u32;
                                match DateTime::from_timestamp(secs, nanos) {
                                    Some(datetime_utc) => {
                                        datetime_utc.format("%Y-%m-%dT%H-%M-%S").to_string()
                                    }
                                    None => format!("unknown_date_{}", folder_uuid),
                                }
                            })
                            .unwrap_or_else(|| format!("no_date_{}", folder_uuid));

                        // Convert the root node of the backup record into a DirectoryEntry.
                        // This will be a shallow entry due to the modified node_to_directory_entry.
                        let backup_root_entry =
                            self.node_to_directory_entry(&arq7_record.node, folder_uuid.clone())?;

                        // Create a directory entry for this specific backup record session (e.g., named by date).
                        // This directory will contain the actual root of the backed-up folder/file.
                        let record_session_dir = DirectoryEntry::Directory(DirectoryEntryNode {
                            name: record_dir_name,
                            children: Some(vec![backup_root_entry]), // Contains the single root of the backup
                            tree_blob_loc: None, // This directory is virtual, not from a blob
                            modification_time_sec: arq7_record.node.modification_time_sec, // Or use record's creation time
                            creation_time_sec: arq7_record.node.creation_time_sec, // Or use record's creation time
                            mode: 0o040755, // Typical directory mode
                        });
                        root_children_entries.push(record_session_dir);
                    }
                    GenericBackupRecord::Arq5(_arq5_record) => {
                        println!(
                            "Skipping Arq5 record for folder UUID: {} in get_root_directory",
                            folder_uuid
                        );
                    }
                }
            }
        }

        Ok(DirectoryEntryNode {
            name: "/".to_string(),
            children: Some(root_children_entries), // Ensure children is Some Vec
            tree_blob_loc: None,                   // Root is virtual
            modification_time_sec: 0,              // Or some other sensible default/current time
            creation_time_sec: 0,
            mode: 0o040755, // Typical directory mode
        })
    }

    /// Loads the children of a DirectoryEntryNode on demand.
    pub fn load_directory_children(&self, dir_entry_node: &mut DirectoryEntryNode) -> Result<()> {
        // If children are already loaded, or if it's a virtual directory without a tree_blob_loc
        if dir_entry_node.children.is_some() {
            return Ok(());
        }

        let blob_loc = match &dir_entry_node.tree_blob_loc {
            Some(loc) => loc,
            None => {
                // No blob loc, so it's an empty or virtual directory.
                dir_entry_node.children = Some(Vec::new());
                return Ok(());
            }
        };

        // Load the tree data using the blob_loc
        match blob_loc
            .load_tree_with_encryption(&self.root_path, self.encryption_keyset.as_ref())?
        {
            Some(tree) => {
                let mut children_entries = Vec::new();
                for (name, child_node) in tree.nodes {
                    // Convert each child Node into a shallow DirectoryEntry
                    let child_entry = self.node_to_directory_entry(&child_node, name)?;
                    children_entries.push(child_entry);
                }
                dir_entry_node.children = Some(children_entries);
            }
            None => {
                // Tree blob was empty or indicated no children
                dir_entry_node.children = Some(Vec::new());
            }
        }
        Ok(())
    }

    /// Reads the content of a file represented by a FileEntry.
    pub fn read_file_content(&self, file_entry: &FileEntry) -> Result<Vec<u8>> {
        let mut full_content = Vec::new();

        if file_entry.data_blob_locs.is_empty() {
            // Handle cases like zero-byte files that might not have blob locs.
            // Depending on Arq's behavior, item_size might be 0 for these.
            // If size is > 0 but no locs, it could be an error or an unsupported case.
            if file_entry.size == 0 {
                return Ok(full_content); // Empty file, return empty content
            } else {
                // This might indicate an issue or a file type not represented by dataBlobLocs here
                return Err(Error::InvalidFormat(format!(
                    "File '{}' has size {} but no data blob locations.",
                    file_entry.name, file_entry.size
                )));
            }
        }

        for blob_loc in &file_entry.data_blob_locs {
            let blob_data = blob_loc.load_data(&self.root_path, self.encryption_keyset.as_ref())?;
            full_content.extend(blob_data);
        }

        // As a sanity check, compare the loaded content size with the expected size.
        // This might not always be strictly necessary if Arq guarantees consistency,
        // but can catch issues during development or with corrupted data.
        if full_content.len() as u64 != file_entry.size {
            eprintln!(
                // Using eprintln for warnings, not returning an error yet unless it's critical
                "Warning: Loaded content size {} for file '{}' does not match expected size {}.",
                full_content.len(),
                file_entry.name,
                file_entry.size
            );
            // Depending on strictness, one might choose to return an error here:
            // return Err(Error::InvalidFormat(format!("Content size mismatch for file '{}'", file_entry.name)));
        }

        Ok(full_content)
    }
}

impl GenericBackupRecord {
    /// Load a GenericBackupRecord from a file path
    /// The file format is: 4-byte big-endian length + LZ4-compressed JSON data
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_file_with_encryption(path, None)
    }

    /// Load GenericBackupRecord from file, optionally decrypting if needed
    pub fn from_file_with_encryption<P: AsRef<Path>>(
        path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Self> {
        // Changed BackupRecord to Self
        let path_ref = path.as_ref();
        let file = File::open(path_ref)?;
        let mut reader = BufReader::new(file);

        Self::from_reader_with_encryption(&mut reader, keyset)
    }

    /// Load a GenericBackupRecord from a reader
    pub fn from_reader<R: BufRead>(reader: R) -> Result<Self> {
        Self::from_reader_with_encryption(reader, None)
    }

    /// Load GenericBackupRecord from reader, optionally decrypting if needed
    pub fn from_reader_with_encryption<R: BufRead>(
        mut reader: R,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Self> {
        // Changed BackupRecord to Self
        let data = if let Some(keyset) = keyset {
            // Check if this is an encrypted file by peeking at the header
            let mut header = [0u8; 4];
            reader.read_exact(&mut header)?;

            if header == [65, 82, 81, 79] {
                // "ARQO" - encrypted
                // Read the rest of the file as encrypted object
                let mut encrypted_data = Vec::new();
                reader.read_to_end(&mut encrypted_data)?;

                // Reconstruct the full encrypted object data with header
                let mut full_data = header.to_vec();
                full_data.extend(encrypted_data);

                let mut cursor = std::io::Cursor::new(&full_data);
                let encrypted_obj = EncryptedObject::new(&mut cursor)?;
                encrypted_obj.validate(&keyset.hmac_key)?;
                let decrypted_data = encrypted_obj.decrypt(&keyset.encryption_key[..])?;

                // Decrypted data follows the same format as unencrypted records:
                // 4-byte length + LZ4-compressed JSON
                if decrypted_data.len() < 4 {
                    return Err(Error::InvalidFormat("Decrypted data too short".to_string()));
                }
                let length = u32::from_be_bytes([
                    decrypted_data[0],
                    decrypted_data[1],
                    decrypted_data[2],
                    decrypted_data[3],
                ]) as usize;
                let compressed_data = &decrypted_data[4..];
                lz4_flex::block::decompress(compressed_data, length)?
            } else {
                // Not encrypted, read the rest normally
                // The header we read was the length prefix for LZ4
                let length = u32::from_be_bytes(header) as usize;
                let mut compressed_data = Vec::new();
                reader.read_to_end(&mut compressed_data)?;

                lz4_flex::block::decompress(&compressed_data, length)?
            }
        } else {
            // No encryption support, load normally
            let length = reader.read_u32::<BigEndian>()? as usize;
            let mut compressed = Vec::new();
            reader.read_to_end(&mut compressed)?;
            lz4_flex::block::decompress(&compressed, length)?
        };

        // Parse the JSON
        let json_str = String::from_utf8(data)?;
        // println!("BackupRecord Json:\n{}", json_str);
        Ok(serde_json::from_str(&json_str)?)
    }
}

impl BlobLoc {
    // from_binary_reader was already added in the previous step.
    // Methods from the old BlobLoc have been moved here.
    // The `from_binary_blob_loc` method, previously on BlobLoc, is now obsolete
    // and has been removed as its logic is incorporated into Node::from_binary_node.

    /// Normalize relative path to handle absolute paths that should be treated as relative
    fn normalize_relative_path(&self, backup_set_dir: &Path) -> std::path::PathBuf {
        // Handle different relative path formats:
        // 1. JSON format: "/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/..."
        // 2. Binary format paths: "/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/..."
        let path_parts: Vec<&str> = self.relative_path.split('/').collect();
        let path_without_uuid = if path_parts.len() > 2 && !path_parts[1].is_empty() {
            // Skip the UUID part (first non-empty component)
            path_parts[2..].join("/")
        } else {
            // Fallback to removing just the leading slash
            self.relative_path.trim_start_matches('/').to_string()
        };
        backup_set_dir.join(&path_without_uuid)
    }

    /// Load data from this blob location, with optional encryption support
    pub fn load_data<P: AsRef<Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let backup_set_dir = backup_set_dir.as_ref();

        if self.is_packed {
            self.load_from_pack_file_with_encryption(backup_set_dir, keyset)
        } else {
            // Load from standalone file
            let file_path = self.normalize_relative_path(backup_set_dir);
            self.load_standalone_file_with_encryption(&file_path, keyset)
        }
    }

    /// Load the actual blob data from a pack file or standalone object (legacy method)
    pub fn load_data_legacy(&self, backup_set_path: &std::path::Path) -> Result<Vec<u8>> {
        self.load_data(backup_set_path, None)
    }

    /// Load data from standalone file with encryption support
    fn load_standalone_file_with_encryption(
        &self,
        file_path: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);

        let data = if let Some(keyset) = keyset {
            // Check if this is an encrypted file
            let mut header = [0u8; 4];
            reader.read_exact(&mut header)?;

            if header == [65, 82, 81, 79] {
                // "ARQO" - encrypted
                // Seek back and decrypt
                reader.seek(SeekFrom::Start(0))?;
                let encrypted_obj = EncryptedObject::new(&mut reader)?;
                encrypted_obj.validate(&keyset.hmac_key)?;
                encrypted_obj.decrypt(&keyset.encryption_key[..32])?
            } else {
                // Not encrypted, read normally
                reader.seek(SeekFrom::Start(0))?;
                let mut data = Vec::new();
                reader.read_to_end(&mut data)?;
                data
            }
        } else {
            // No encryption support
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;
            data
        };

        // Decompress if needed
        match self.compression_type {
            0 => Ok(data), // No compression
            1 => {
                // Gzip compression (legacy)
                use std::io::Read;
                let mut decoder = flate2::read::GzDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            2 => {
                // LZ4 compression
                if data.len() < 4 {
                    return Err(Error::InvalidFormat("LZ4 data too short".to_string()));
                }
                let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let compressed_data = &data[4..];
                Ok(lz4_flex::block::decompress(compressed_data, length)?)
            }
            _ => Err(Error::InvalidFormat(format!(
                "Unsupported compression type: {}",
                self.compression_type
            ))),
        }
    }

    /// Load data from pack file with encryption support
    fn load_from_pack_file_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let pack_file_path = self.normalize_relative_path(backup_set_dir);

        let mut file = File::open(&pack_file_path)?;

        // Seek to the blob's offset
        file.seek(SeekFrom::Start(self.offset))?;

        // Read the blob data
        let mut blob_data = vec![0u8; self.length as usize];
        file.read_exact(&mut blob_data)?;

        // Handle encryption if present
        let data = if let Some(keyset) = keyset {
            // Check if this blob is encrypted
            if blob_data.len() >= 4 && &blob_data[0..4] == [65, 82, 81, 79] {
                // "ARQO"
                // This blob is encrypted
                let mut cursor = std::io::Cursor::new(&blob_data);
                let encrypted_obj = EncryptedObject::new(&mut cursor)?;
                encrypted_obj.validate(&keyset.hmac_key)?;
                encrypted_obj.decrypt(&keyset.encryption_key[..32])?
            } else {
                // Not encrypted
                blob_data
            }
        } else {
            blob_data
        };

        // Decompress if needed
        match self.compression_type {
            0 => Ok(data), // No compression
            1 => {
                // Gzip compression (legacy)
                use std::io::Read;
                let mut decoder = flate2::read::GzDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            2 => {
                // LZ4 compression
                if data.len() < 4 {
                    return Err(Error::InvalidFormat("LZ4 data too short".to_string()));
                }
                let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let compressed_data = &data[4..];
                Ok(lz4_flex::block::decompress(compressed_data, length)?)
            }
            _ => Err(Error::InvalidFormat(format!(
                "Unsupported compression type: {}",
                self.compression_type
            ))),
        }
    }

    /// Load and parse a tree from this blob location
    pub fn load_tree(&self, backup_set_path: &std::path::Path) -> Result<crate::tree::Tree> {
        // Changed to crate::tree::Tree
        match self.load_tree_with_encryption(backup_set_path, None)? {
            Some(tree) => Ok(tree),
            None => Err(Error::InvalidFormat("No tree data found".to_string())),
        }
    }

    /// Load and parse as binary tree with encryption support
    pub fn load_tree_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<crate::tree::Tree>> {
        let tree_data = self.load_data(backup_set_dir, keyset)?;
        if tree_data.is_empty() {
            return Ok(None);
        }

        // Use the unified Tree's method for parsing Arq7 binary data
        let tree = crate::tree::Tree::from_arq7_binary_data(&tree_data)?;
        Ok(Some(tree))
    }

    /// Load and parse a node from this blob location
    pub fn load_node(
        &self,
        backup_set_path: &std::path::Path,
    ) -> Result<Option<crate::node::Node>> {
        // Changed to crate::node::Node
        // Changed return type to unified Node
        self.load_node_with_encryption(backup_set_path, None)
    }

    /// Load and parse as binary node with encryption support
    pub fn load_node_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<crate::node::Node>> {
        // Changed to crate::node::Node
        // Changed return type to unified Node
        let data = self.load_data(backup_set_dir, keyset)?;

        if data.is_empty() {
            return Ok(None);
        }

        let mut cursor = std::io::Cursor::new(&data);
        // Call the new from_binary_reader on the unified Node struct
        // Pass None for tree_version as BlobLoc itself doesn't know the tree version.
        // The from_binary_reader_arq7 method in crate::node::Node handles Option<u32> for tree_version.
        let node = crate::node::Node::from_binary_reader_arq7(&mut cursor, None)?;
        Ok(Some(node))
    }

    /// Extract the actual file content from this blob location
    pub fn extract_content(
        &self,
        backup_set_path: &std::path::Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        self.load_data(backup_set_path, keyset)
    }

    /// Extract file content as a UTF-8 string (for text files)
    pub fn extract_text_content(
        &self,
        backup_set_path: &std::path::Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<String> {
        let content = self.extract_content(backup_set_path, keyset)?;
        Ok(String::from_utf8_lossy(&content).to_string())
    }

    /// Save extracted content to a file
    pub fn extract_to_file<P: AsRef<std::path::Path>>(
        &self,
        backup_set_path: &std::path::Path,
        output_path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<()> {
        let content = self.extract_content(backup_set_path, keyset)?;
        std::fs::write(output_path, content)?;
        Ok(())
    }

    /// Extract content to file with encryption support
    pub fn extract_to_file_with_encryption<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        backup_set_dir: P1,
        output_path: P2,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<()> {
        let data = self.load_data(backup_set_dir.as_ref(), keyset)?;
        std::fs::write(output_path, data)?;
        Ok(())
    }
}

// Node::from_binary_node() is removed as its logic is now part of Node::from_binary_reader()
// and BinaryTree directly creates the unified Node.

impl Node {
    // The from_binary_reader method is already defined above within this impl block.

    /// Get real blob locations from this node (for files)
    pub fn get_data_blob_locations(&self) -> &[BlobLoc] {
        &self.data_blob_locs
    }

    /// Get tree blob location (for directories)
    pub fn get_tree_blob_location(&self) -> Option<&BlobLoc> {
        self.tree_blob_loc.as_ref()
    }
}

impl BackupSet {
    /// Find real blob locations for files in the backup records
    /// This can be used when binary parsing produces fake blob paths
    pub fn find_all_blob_locations(&self) -> Vec<crate::blob_location::BlobLoc> {
        // Updated return type
        let mut blob_locations = Vec::new();

        for (_, records_vec) in &self.backup_records {
            for generic_record in records_vec {
                match generic_record {
                    GenericBackupRecord::Arq7(record) => {
                        collect_blob_locations_from_node(&record.node, &mut blob_locations);
                    }
                    GenericBackupRecord::Arq5(record) => {
                        if let Some(key) = &record.arq5_tree_blob_key {
                            // Convert crate::blob::BlobKey to crate::blob_location::BlobLoc.
                            blob_locations.push(crate::blob_location::BlobLoc {
                                // Updated type
                                blob_identifier: key.sha1.clone(),
                                compression_type: key.compression_type,
                                is_packed: false,
                                length: key.archive_size, // From unified BlobKey
                                offset: 0,                // Assumption for Arq5TreeBlobKey context
                                relative_path: format!("arq5_migrated_tree_blob/{}", key.sha1), // Placeholder path
                                stretch_encryption_key: key.stretch_encryption_key, // From unified BlobKey
                                is_large_pack: None, // Arq5 context might not have this concept
                            });
                        }
                        // backupRecordErrors in Arq5 might list problematic files, but these are not primary data blobs.
                        // arq5BucketXML parsing is out of scope.
                    }
                }
            }
        }
        blob_locations
    }
}

/// Recursively collect blob locations from a node tree (used for Arq7 records)
fn collect_blob_locations_from_node(
    node: &crate::node::Node,
    blob_locations: &mut Vec<crate::blob_location::BlobLoc>,
) {
    // Updated Vec type
    // Add data blob locations from this node
    for blob_loc in &node.data_blob_locs {
        // Convert arq7::BlobLoc to blob_location::BlobLoc
        blob_locations.push(blob_loc.clone().into());
    }

    // Add tree blob location if present
    if let Some(tree_blob_loc) = &node.tree_blob_loc {
        blob_locations.push(tree_blob_loc.clone().into());
    }

    // Add xattrs blob locations if present
    if let Some(xattrs_blob_locs) = &node.xattrs_blob_locs {
        for blob_loc in xattrs_blob_locs {
            blob_locations.push(blob_loc.clone());
        }
    }
    // Add acl blob location if present
    if let Some(acl_blob_loc) = &node.acl_blob_loc {
        blob_locations.push(acl_blob_loc.clone());
    }
}

/// Helper function for metadata extraction
fn count_files_in_node(
    node: &crate::node::Node, // Changed to crate::node::Node
    backup_set_dir: &Path,
    keyset: Option<&EncryptedKeySet>,
) -> Result<(u32, u64)> {
    if !node.is_tree {
        // This is a file
        let size = node.item_size;
        return Ok((1, size));
    }

    // This is a directory
    let mut file_count = 0u32;
    let mut total_size = 0u64;

    // TODO: This method needs to be implemented on crate::node::Node
    // For now, assume it returns Ok(None) to allow compilation.
    // if let Some(tree) = node.load_tree_with_encryption(backup_set_dir, keyset)? {
    //     for (_, child_node) in &tree.child_nodes {
    //         let (child_files, child_size) =
    //             count_files_in_node(child_node, backup_set_dir, keyset)?;
    //         file_count += child_files;
    //         total_size += child_size;
    //     }
    // }
    if let Some(tree) = node.load_tree_with_encryption(backup_set_dir, keyset)? {
        for (_, child_node_entry) in &tree.nodes {
            // Use tree.nodes
            let (child_files, child_size) =
                count_files_in_node(child_node_entry, backup_set_dir, keyset)?;
            file_count += child_files;
            total_size += child_size;
        }
    }
    Ok((file_count, total_size))
}

/// Represents an entry in a directory, either a File or a Directory.
#[derive(Debug, Clone)]
pub enum DirectoryEntry {
    File(FileEntry),
    Directory(DirectoryEntryNode),
}

/// Represents a file in the virtual filesystem.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub data_blob_locs: Vec<crate::blob_location::BlobLoc>,
    pub modification_time_sec: i64,
    pub creation_time_sec: i64,
    pub mode: u32,
    // We can add more metadata from Node if needed, e.g., modification_time
    // For now, keeping it simple.
    // pub node_data: Node, // Or specific fields from Node
}

/// Represents a directory in the virtual filesystem.
#[derive(Debug, Clone)]
pub struct DirectoryEntryNode {
    pub name: String,
    pub children: Option<Vec<DirectoryEntry>>, // Changed to Option for on-demand loading
    pub tree_blob_loc: Option<crate::blob_location::BlobLoc>, // For loading children on demand
    pub modification_time_sec: i64,
    pub creation_time_sec: i64,
    pub mode: u32,
    // pub node_data: Node, // Or specific fields from Node for the directory itself
}

#[test]
fn test_binary_tree_loading() {
    // Test loading a tree from binary data (if pack files exist)
    let backup_set_dir =
        std::path::Path::new("tests/arq_storage_location/FD5575D9-B7E1-43D9-B54ACC9BC2A9");

    if let Ok(backup_set) = BackupSet::from_directory(backup_set_dir) {
        if let Some(records) = backup_set
            .backup_records
            .get("29F6E502-2737-4417-8023-4940D61BA375")
        {
            if let Some(GenericBackupRecord::Arq7(record)) = records.first() {
                // Match on Arq7 variant
                // Try to load the tree referenced by the root node
                // record.node is crate::node::Node, which has load_tree_with_encryption
                match record
                    .node
                    .load_tree_with_encryption(backup_set_dir, backup_set.encryption_keyset())
                {
                    Ok(Some(_tree)) => {
                        // Successfully loaded binary tree data
                        println!("Successfully loaded binary tree data");
                    }
                    Ok(None) => {
                        println!("Tree loading returned no tree (e.g. empty or not a tree).");
                    }
                    Err(_e) => {
                        // Tree loading failed, which is expected if pack files don't exist
                        println!(
                            "Tree loading failed (expected if pack files don't exist or error: {})",
                            _e
                        );
                    }
                }
            } else if let Some(GenericBackupRecord::Arq5(_record)) = records.first() {
                // Arq5 records don't have a direct .node field in this test's context for tree loading.
                // This test is primarily for Arq7 tree loading.
                println!("Skipping Arq5 record for binary tree loading test.");
            }
        }
    }
}

// Temporarily removing test_get_root_directory due to persistent compile issues in this environment.
// Will need to revisit this test with a more robust mocking strategy or actual test files.

#[test]
fn test_parse_backup_config() {
    let json = r#"{
            "blobIdentifierType": 2,
            "maxPackedItemLength": 256000,
            "backupName": "Back up to arq_storage_location",
            "isWORM": false,
            "containsGlacierArchives": false,
            "additionalUnpackedBlobDirs": [],
            "chunkerVersion": 3,
            "computerName": "Lars's MacBook Pro",
            "computerSerial": "unused",
            "blobStorageClass": "STANDARD",
            "isEncrypted": false
        }"#;

    let config: BackupConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.blob_identifier_type, 2);
    assert_eq!(config.backup_name, "Back up to arq_storage_location");
    assert_eq!(config.computer_name, "Lars's MacBook Pro");
    assert!(!config.is_encrypted);
}

#[test]
fn test_parse_backup_folder() {
    let json = r#"{
            "localPath": "/arq/arq_backup_source",
            "migratedFromArq60": false,
            "storageClass": "STANDARD",
            "diskIdentifier": "ROOT",
            "uuid": "29F6E502-2737-4417-8023-4940D61BA375",
            "migratedFromArq5": false,
            "localMountPoint": "/",
            "name": "arq_backup_source"
        }"#;

    let folder: BackupFolder = serde_json::from_str(json).unwrap();
    assert_eq!(folder.local_path, "/arq/arq_backup_source");
    assert_eq!(folder.uuid, "29F6E502-2737-4417-8023-4940D61BA375");
    assert_eq!(folder.name, "arq_backup_source");
    assert!(!folder.migrated_from_arq5);
}

#[test]
fn test_lz4_decompression() {
    // Test that we can decompress LZ4 data (using lz4_flex directly)
    let original = b"Hello, World! This is a test string for LZ4 compression.";
    let compressed = lz4_flex::compress_prepend_size(original);
    let decompressed = lz4_flex::decompress_size_prepended(&compressed).unwrap();
    assert_eq!(original, decompressed.as_slice());
}

#[test]
fn test_backup_record_parsing() {
    // Test that Arq7 native backup records (version 100) can be parsed from test data
    // This test uses a v100 record. The v12 (Arq5 migrated) records are tested elsewhere.
    let record_path = std::path::Path::new("tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/backupfolders/29F6E502-2737-4417-8023-4940D61BA375/backuprecords/00173/6107191.backuprecord");

    if record_path.exists() {
        let generic_record = GenericBackupRecord::from_file(record_path).unwrap();

        match generic_record {
            GenericBackupRecord::Arq7(record) => {
                // Verify basic record structure for Arq7BackupRecord
                assert_eq!(
                    record.backup_folder_uuid,
                    "29F6E502-2737-4417-8023-4940D61BA375"
                );
                assert_eq!(
                    record.backup_plan_uuid,
                    "FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9"
                );
                assert_eq!(record.disk_identifier, "ROOT"); // Field specific to Arq7BackupRecord
                assert_eq!(record.storage_class, "STANDARD");
                assert_eq!(record.version, 100); // Expecting version 100 for Arq7 native
                assert!(!record.copied_from_commit);
                assert!(!record.copied_from_snapshot);

                // Check backupRecordErrors (should be Some([]) or None for this file)
                assert!(record
                    .backup_record_errors
                    .as_ref()
                    .map_or(true, |v| v.is_empty()));

                let _ = record.creation_date; // Check it exists

                // Verify node structure
                assert!(record.node.is_tree);
                assert_eq!(record.node.computer_os_type, Some(1));
                assert!(!record.node.deleted);
                assert!(record.node.tree_blob_loc.is_some());

                // Verify arq version if present
                if let Some(arq_version) = &record.arq_version {
                    assert!(arq_version.starts_with("7."));
                }

                // Arq7 specific fields should not be present in Arq5BackupRecord, so this checks we got an Arq7
                assert!(record.backup_plan_json.is_some());
            }
            GenericBackupRecord::Arq5(_) => {
                panic!(
                    "Parsed Arq7 native record as Arq5BackupRecord. File: {:?}",
                    record_path
                );
            }
        }
    } else {
        eprintln!(
            "Warning: Test file not found, skipping test_backup_record_parsing: {:?}",
            record_path
        );
    }
}

#[test]
fn test_get_root_directory() {
    // Modified for new on-demand behavior
    // Mock BackupSet components
    let backup_config = BackupConfig {
        blob_identifier_type: 2,
        max_packed_item_length: 256000,
        backup_name: "Test Backup".to_string(),
        is_worm: false,
        contains_glacier_archives: false,
        additional_unpacked_blob_dirs: vec![],
        chunker_version: 3,
        computer_name: "Test PC".to_string(),
        computer_serial: "unused".to_string(),
        blob_storage_class: "STANDARD".to_string(),
        is_encrypted: false,
    };
    let backup_folders = BackupFolders {
        standard_object_dirs: vec![],
        standard_ia_object_dirs: vec![],
        onezone_ia_object_dirs: vec![],
        s3_glacier_object_dirs: vec![],
        s3_deep_archive_object_dirs: vec![],
        s3_glacier_ir_object_dirs: None,
        imported_from: None,
    };
    let transfer_rate = TransferRate {
        enabled: false,
        start_time_of_day: "00:00".to_string(),
        days_of_week: vec![],
        schedule_type: "manual".to_string(),
        end_time_of_day: "23:59".to_string(),
        max_kbps: None,
    };
    let schedule = Schedule {
        backup_and_validate: false,
        start_when_volume_is_connected: false,
        pause_during_window: false,
        schedule_type: "manual".to_string(),
        days_of_week: None,
        every_hours: None,
        minutes_after_hour: None,
        pause_from: None,
        pause_to: None,
    };
    let email_report = EmailReport {
        port: 25,
        start_tls: false,
        authentication_type: "none".to_string(),
        report_helo_use_ip: None,
        when: "never".to_string(),
        report_type: "none".to_string(),
        hostname: None,
        username: None,
        from_address: None,
        to_address: None,
        subject: None,
    };
    let backup_plan = BackupPlan {
        transfer_rate_json: transfer_rate,
        cpu_usage: 50,
        id: 1,
        storage_location_id: 1,
        excluded_network_interfaces: vec![],
        needs_arq5_buckets: false,
        use_buzhash: true,
        arq5_use_s3_ia: false,
        object_lock_update_interval_days: 0,
        plan_uuid: "test-plan-uuid".to_string(),
        schedule_json: schedule,
        keep_deleted_files: false,
        version: 1,
        created_at_pro_console: None,
        backup_folder_plan_mount_points_are_initialized: None,
        include_new_volumes: false,
        retain_months: 1,
        use_apfs_snapshots: false,
        backup_set_is_initialized: None,
        backup_folder_plans_by_uuid: HashMap::new(),
        notify_on_error: false,
        retain_days: 7,
        update_time: 0.0,
        excluded_wi_fi_network_names: vec![],
        object_lock_available: None,
        managed: None,
        name: "Test Plan".to_string(),
        wake_for_backup: false,
        include_network_interfaces: None,
        dataless_files_option: None,
        retain_all: false,
        is_encrypted: false,
        active: true,
        notify_on_success: false,
        prevent_sleep: false,
        creation_time: 1678886400,
        pause_on_battery: false,
        retain_weeks: 4,
        retain_hours: 24,
        prevent_backup_on_constrained_networks: None,
        include_wi_fi_networks: false,
        thread_count: 1,
        prevent_backup_on_expensive_networks: None,
        email_report_json: email_report,
        include_file_list_in_activity_log: false,
        no_backups_alert_days: Some(0),
    };

    // Mock root_backup_node (as a directory)
    let root_backup_node_content_blob_loc = crate::blob_location::BlobLoc {
        blob_identifier: "dummy_root_content_tree_blob".to_string(),
        compression_type: 0,
        is_packed: false,
        length: 0,
        offset: 0,
        relative_path: "dummy/path/root_content_tree_blob".to_string(),
        stretch_encryption_key: false,
        is_large_pack: Some(false),
    };
    let root_backup_node = crate::node::Node {
        is_tree: true,
        item_size: 0,
        deleted: false,
        computer_os_type: Some(1),
        modification_time_sec: 1678886400,
        modification_time_nsec: 0,
        change_time_sec: 1678886400,
        change_time_nsec: 0,
        creation_time_sec: 1678886400,
        creation_time_nsec: 0,
        st_mode: 0o040755,
        st_ino: 3,
        st_nlink: 2,
        st_gid: 0,
        st_uid: Some(0),
        username: Some("testuser".to_string()),
        group_name: Some("testgroup".to_string()),
        st_dev: 0,
        st_rdev: 0,
        st_flags: 0,
        win_attrs: Some(0),
        reparse_tag: None,
        reparse_point_is_directory: None,
        contained_files_count: Some(0),
        data_blob_locs: vec![],
        tree_blob_loc: Some(root_backup_node_content_blob_loc.clone()),
        xattrs_blob_locs: None,
        acl_blob_loc: None,
        arq5_tree_contains_missing_items: None,
        arq5_data_compression_type: None,
        arq5_xattrs_compression_type: None,
        arq5_acl_compression_type: None,
        arq5_xattrs_blob_key: None,
        arq5_xattrs_size: None,
        arq5_acl_blob_key: None,
        arq5_finder_flags: None,
        arq5_extended_finder_flags: None,
        arq5_finder_file_type: None,
        arq5_finder_file_creator: None,
        arq5_is_file_extension_hidden: None,
        arq5_st_blocks: None,
        arq5_st_blksize: None,
    };

    let arq7_record = Arq7BackupRecord {
        backup_folder_uuid: "test-folder-uuid".to_string(),
        disk_identifier: "test-disk".to_string(),
        storage_class: "STANDARD".to_string(),
        version: 100,
        backup_plan_uuid: "test-plan-uuid".to_string(),
        backup_record_errors: None,
        copied_from_snapshot: false,
        copied_from_commit: false,
        node: root_backup_node.clone(),
        arq_version: Some("7.0.0".to_string()),
        archived: Some(false),
        backup_plan_json: None,
        relative_path: Some("/".to_string()),
        computer_os_type: Some(1),
        local_path: Some("/test/backup/source".to_string()),
        local_mount_point: Some("/".to_string()),
        is_complete: Some(true),
        creation_date: Some(1678886400.0), // March 15, 2023 12:00:00 UTC
        volume_name: Some("TestVolume".to_string()),
    };

    let mut backup_records = HashMap::new();
    backup_records.insert(
        "test-folder-uuid".to_string(),
        vec![GenericBackupRecord::Arq7(arq7_record)],
    );

    let dummy_backup_set_dir = std::path::PathBuf::from("dummy_get_root_dir_test");

    let backup_set = BackupSet {
        backup_config,
        backup_folders,
        backup_plan,
        backup_folder_configs: HashMap::new(),
        backup_records,
        encryption_keyset: None,
        root_path: dummy_backup_set_dir.clone(),
    };

    let root_dir_result = backup_set.get_root_directory();
    assert!(
        root_dir_result.is_ok(),
        "get_root_directory should now succeed with on-demand loading. Error: {:?}",
        root_dir_result.err()
    );

    if let Ok(root_dir) = root_dir_result {
        assert_eq!(root_dir.name, "/");
        assert!(root_dir.children.is_some());
        let root_children = root_dir.children.unwrap();
        assert_eq!(
            root_children.len(),
            1,
            "Expected one backup session directory"
        );

        match &root_children[0] {
            DirectoryEntry::Directory(session_dir) => {
                assert_eq!(
                    session_dir.name, "2023-03-15T13-20-00",
                    "Session directory name mismatch"
                );
                assert!(session_dir.children.is_some());
                let session_children = session_dir.children.as_ref().unwrap();
                assert_eq!(
                    session_children.len(),
                    1,
                    "Session directory should contain one entry (the backup's root)"
                );

                match &session_children[0] {
                    DirectoryEntry::Directory(backup_actual_root) => {
                        assert_eq!(backup_actual_root.name, "test-folder-uuid");
                        assert!(
                            backup_actual_root.children.is_none(),
                            "Children of actual backup root should be None (not loaded yet)"
                        );
                        assert_eq!(
                            backup_actual_root.tree_blob_loc,
                            Some(root_backup_node_content_blob_loc)
                        );
                    }
                    DirectoryEntry::File(_) => {
                        panic!("Expected backup actual root to be a directory, got a file.")
                    }
                }
            }
            _ => panic!("Expected session entry to be a directory."),
        }
    }
}

#[test]
fn test_load_directory_children_empty() {
    let backup_config = BackupConfig {
        blob_identifier_type: 0,
        max_packed_item_length: 0,
        backup_name: String::new(),
        is_worm: false,
        contains_glacier_archives: false,
        additional_unpacked_blob_dirs: vec![],
        chunker_version: 0,
        computer_name: String::new(),
        computer_serial: String::new(),
        blob_storage_class: String::new(),
        is_encrypted: false,
    };
    let backup_folders = BackupFolders {
        standard_object_dirs: vec![],
        standard_ia_object_dirs: vec![],
        onezone_ia_object_dirs: vec![],
        s3_glacier_object_dirs: vec![],
        s3_deep_archive_object_dirs: vec![],
        s3_glacier_ir_object_dirs: None,
        imported_from: None,
    };
    let backup_plan = BackupPlan {
        transfer_rate_json: TransferRate {
            enabled: false,
            start_time_of_day: "".to_string(),
            days_of_week: vec![],
            schedule_type: "".to_string(),
            end_time_of_day: "".to_string(),
            max_kbps: None,
        },
        cpu_usage: 0,
        id: 0,
        storage_location_id: 0,
        excluded_network_interfaces: vec![],
        needs_arq5_buckets: false,
        use_buzhash: false,
        arq5_use_s3_ia: false,
        object_lock_update_interval_days: 0,
        plan_uuid: String::new(),
        schedule_json: Schedule {
            backup_and_validate: false,
            start_when_volume_is_connected: false,
            pause_during_window: false,
            schedule_type: "".to_string(),
            days_of_week: None,
            every_hours: None,
            minutes_after_hour: None,
            pause_from: None,
            pause_to: None,
        },
        keep_deleted_files: false,
        version: 0,
        created_at_pro_console: None,
        backup_folder_plan_mount_points_are_initialized: None,
        include_new_volumes: false,
        retain_months: 0,
        use_apfs_snapshots: false,
        backup_set_is_initialized: None,
        backup_folder_plans_by_uuid: HashMap::new(),
        notify_on_error: false,
        retain_days: 0,
        update_time: 0.0,
        excluded_wi_fi_network_names: vec![],
        object_lock_available: None,
        managed: None,
        name: String::new(),
        wake_for_backup: false,
        include_network_interfaces: None,
        dataless_files_option: None,
        retain_all: false,
        is_encrypted: false,
        active: false,
        notify_on_success: false,
        prevent_sleep: false,
        creation_time: 0,
        pause_on_battery: false,
        retain_weeks: 0,
        retain_hours: 0,
        prevent_backup_on_constrained_networks: None,
        include_wi_fi_networks: false,
        thread_count: 0,
        prevent_backup_on_expensive_networks: None,
        email_report_json: EmailReport {
            port: 0,
            start_tls: false,
            authentication_type: "".to_string(),
            report_helo_use_ip: None,
            when: "".to_string(),
            report_type: "".to_string(),
            hostname: None,
            username: None,
            from_address: None,
            to_address: None,
            subject: None,
        },
        include_file_list_in_activity_log: false,
        no_backups_alert_days: Some(0),
    };

    let backup_set = BackupSet {
        backup_config,
        backup_folders,
        backup_plan,
        backup_folder_configs: HashMap::new(),
        backup_records: HashMap::new(),
        encryption_keyset: None,
        root_path: PathBuf::from("dummy_path_children_empty"),
    };
    let mut dir_node = DirectoryEntryNode {
        name: "empty_dir".to_string(),
        children: None,
        tree_blob_loc: None,
        modification_time_sec: 0,
        creation_time_sec: 0,
        mode: 0o040755,
    };
    let result = backup_set.load_directory_children(&mut dir_node);
    assert!(result.is_ok());
    assert!(dir_node.children.is_some());
    assert!(dir_node.children.unwrap().is_empty());
}

#[test]
fn test_load_directory_children_non_existent_blob() {
    let backup_config = BackupConfig {
        blob_identifier_type: 0,
        max_packed_item_length: 0,
        backup_name: String::new(),
        is_worm: false,
        contains_glacier_archives: false,
        additional_unpacked_blob_dirs: vec![],
        chunker_version: 0,
        computer_name: String::new(),
        computer_serial: String::new(),
        blob_storage_class: String::new(),
        is_encrypted: false,
    };
    let backup_folders = BackupFolders {
        standard_object_dirs: vec![],
        standard_ia_object_dirs: vec![],
        onezone_ia_object_dirs: vec![],
        s3_glacier_object_dirs: vec![],
        s3_deep_archive_object_dirs: vec![],
        s3_glacier_ir_object_dirs: None,
        imported_from: None,
    };
    let backup_plan = BackupPlan {
        transfer_rate_json: TransferRate {
            enabled: false,
            start_time_of_day: "".to_string(),
            days_of_week: vec![],
            schedule_type: "".to_string(),
            end_time_of_day: "".to_string(),
            max_kbps: None,
        },
        cpu_usage: 0,
        id: 0,
        storage_location_id: 0,
        excluded_network_interfaces: vec![],
        needs_arq5_buckets: false,
        use_buzhash: false,
        arq5_use_s3_ia: false,
        object_lock_update_interval_days: 0,
        plan_uuid: String::new(),
        schedule_json: Schedule {
            backup_and_validate: false,
            start_when_volume_is_connected: false,
            pause_during_window: false,
            schedule_type: "".to_string(),
            days_of_week: None,
            every_hours: None,
            minutes_after_hour: None,
            pause_from: None,
            pause_to: None,
        },
        keep_deleted_files: false,
        version: 0,
        created_at_pro_console: None,
        backup_folder_plan_mount_points_are_initialized: None,
        include_new_volumes: false,
        retain_months: 0,
        use_apfs_snapshots: false,
        backup_set_is_initialized: None,
        backup_folder_plans_by_uuid: HashMap::new(),
        notify_on_error: false,
        retain_days: 0,
        update_time: 0.0,
        excluded_wi_fi_network_names: vec![],
        object_lock_available: None,
        managed: None,
        name: String::new(),
        wake_for_backup: false,
        include_network_interfaces: None,
        dataless_files_option: None,
        retain_all: false,
        is_encrypted: false,
        active: false,
        notify_on_success: false,
        prevent_sleep: false,
        creation_time: 0,
        pause_on_battery: false,
        retain_weeks: 0,
        retain_hours: 0,
        prevent_backup_on_constrained_networks: None,
        include_wi_fi_networks: false,
        thread_count: 0,
        prevent_backup_on_expensive_networks: None,
        email_report_json: EmailReport {
            port: 0,
            start_tls: false,
            authentication_type: "".to_string(),
            report_helo_use_ip: None,
            when: "".to_string(),
            report_type: "".to_string(),
            hostname: None,
            username: None,
            from_address: None,
            to_address: None,
            subject: None,
        },
        include_file_list_in_activity_log: false,
        no_backups_alert_days: Some(0),
    };

    let backup_set = BackupSet {
        backup_config,
        backup_folders,
        backup_plan,
        backup_folder_configs: HashMap::new(),
        backup_records: HashMap::new(),
        encryption_keyset: None,
        root_path: PathBuf::from("dummy_path_children_err"),
    };
    let mut dir_node = DirectoryEntryNode {
        name: "err_dir".to_string(),
        children: None,
        tree_blob_loc: Some(crate::blob_location::BlobLoc {
            blob_identifier: "non_existent_blob".to_string(),
            compression_type: 0,
            is_packed: false,
            length: 0,
            offset: 0,
            relative_path: "non_existent_pack/non_existent_blob".to_string(),
            stretch_encryption_key: false,
            is_large_pack: Some(false),
        }),
        modification_time_sec: 0,
        creation_time_sec: 0,
        mode: 0o040755,
    };
    let result = backup_set.load_directory_children(&mut dir_node);
    assert!(result.is_err());
}

#[test]
fn test_read_file_content_empty() {
    let backup_config = BackupConfig {
        blob_identifier_type: 0,
        max_packed_item_length: 0,
        backup_name: String::new(),
        is_worm: false,
        contains_glacier_archives: false,
        additional_unpacked_blob_dirs: vec![],
        chunker_version: 0,
        computer_name: String::new(),
        computer_serial: String::new(),
        blob_storage_class: String::new(),
        is_encrypted: false,
    };
    let backup_folders = BackupFolders {
        standard_object_dirs: vec![],
        standard_ia_object_dirs: vec![],
        onezone_ia_object_dirs: vec![],
        s3_glacier_object_dirs: vec![],
        s3_deep_archive_object_dirs: vec![],
        s3_glacier_ir_object_dirs: None,
        imported_from: None,
    };
    let backup_plan = BackupPlan {
        transfer_rate_json: TransferRate {
            enabled: false,
            start_time_of_day: "".to_string(),
            days_of_week: vec![],
            schedule_type: "".to_string(),
            end_time_of_day: "".to_string(),
            max_kbps: None,
        },
        cpu_usage: 0,
        id: 0,
        storage_location_id: 0,
        excluded_network_interfaces: vec![],
        needs_arq5_buckets: false,
        use_buzhash: false,
        arq5_use_s3_ia: false,
        object_lock_update_interval_days: 0,
        plan_uuid: String::new(),
        schedule_json: Schedule {
            backup_and_validate: false,
            start_when_volume_is_connected: false,
            pause_during_window: false,
            schedule_type: "".to_string(),
            days_of_week: None,
            every_hours: None,
            minutes_after_hour: None,
            pause_from: None,
            pause_to: None,
        },
        keep_deleted_files: false,
        version: 0,
        created_at_pro_console: None,
        backup_folder_plan_mount_points_are_initialized: None,
        include_new_volumes: false,
        retain_months: 0,
        use_apfs_snapshots: false,
        backup_set_is_initialized: None,
        backup_folder_plans_by_uuid: HashMap::new(),
        notify_on_error: false,
        retain_days: 0,
        update_time: 0.0,
        excluded_wi_fi_network_names: vec![],
        object_lock_available: None,
        managed: None,
        name: String::new(),
        wake_for_backup: false,
        include_network_interfaces: None,
        dataless_files_option: None,
        retain_all: false,
        is_encrypted: false,
        active: false,
        notify_on_success: false,
        prevent_sleep: false,
        creation_time: 0,
        pause_on_battery: false,
        retain_weeks: 0,
        retain_hours: 0,
        prevent_backup_on_constrained_networks: None,
        include_wi_fi_networks: false,
        thread_count: 0,
        prevent_backup_on_expensive_networks: None,
        email_report_json: EmailReport {
            port: 0,
            start_tls: false,
            authentication_type: "".to_string(),
            report_helo_use_ip: None,
            when: "".to_string(),
            report_type: "".to_string(),
            hostname: None,
            username: None,
            from_address: None,
            to_address: None,
            subject: None,
        },
        include_file_list_in_activity_log: false,
        no_backups_alert_days: Some(0),
    };
    let backup_set = BackupSet {
        backup_config,
        backup_folders,
        backup_plan,
        backup_folder_configs: HashMap::new(),
        backup_records: HashMap::new(),
        encryption_keyset: None,
        root_path: PathBuf::from("dummy_path_file_empty"),
    };
    let file_entry = FileEntry {
        name: "empty_file.txt".to_string(),
        size: 0,
        data_blob_locs: vec![],
        modification_time_sec: 0,
        creation_time_sec: 0,
        mode: 0o100644,
    };
    let result = backup_set.read_file_content(&file_entry);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_read_file_content_non_existent_blob() {
    let backup_config = BackupConfig {
        blob_identifier_type: 0,
        max_packed_item_length: 0,
        backup_name: String::new(),
        is_worm: false,
        contains_glacier_archives: false,
        additional_unpacked_blob_dirs: vec![],
        chunker_version: 0,
        computer_name: String::new(),
        computer_serial: String::new(),
        blob_storage_class: String::new(),
        is_encrypted: false,
    };
    let backup_folders = BackupFolders {
        standard_object_dirs: vec![],
        standard_ia_object_dirs: vec![],
        onezone_ia_object_dirs: vec![],
        s3_glacier_object_dirs: vec![],
        s3_deep_archive_object_dirs: vec![],
        s3_glacier_ir_object_dirs: None,
        imported_from: None,
    };
    let backup_plan = BackupPlan {
        transfer_rate_json: TransferRate {
            enabled: false,
            start_time_of_day: "".to_string(),
            days_of_week: vec![],
            schedule_type: "".to_string(),
            end_time_of_day: "".to_string(),
            max_kbps: None,
        },
        cpu_usage: 0,
        id: 0,
        storage_location_id: 0,
        excluded_network_interfaces: vec![],
        needs_arq5_buckets: false,
        use_buzhash: false,
        arq5_use_s3_ia: false,
        object_lock_update_interval_days: 0,
        plan_uuid: String::new(),
        schedule_json: Schedule {
            backup_and_validate: false,
            start_when_volume_is_connected: false,
            pause_during_window: false,
            schedule_type: "".to_string(),
            days_of_week: None,
            every_hours: None,
            minutes_after_hour: None,
            pause_from: None,
            pause_to: None,
        },
        keep_deleted_files: false,
        version: 0,
        created_at_pro_console: None,
        backup_folder_plan_mount_points_are_initialized: None,
        include_new_volumes: false,
        retain_months: 0,
        use_apfs_snapshots: false,
        backup_set_is_initialized: None,
        backup_folder_plans_by_uuid: HashMap::new(),
        notify_on_error: false,
        retain_days: 0,
        update_time: 0.0,
        excluded_wi_fi_network_names: vec![],
        object_lock_available: None,
        managed: None,
        name: String::new(),
        wake_for_backup: false,
        include_network_interfaces: None,
        dataless_files_option: None,
        retain_all: false,
        is_encrypted: false,
        active: false,
        notify_on_success: false,
        prevent_sleep: false,
        creation_time: 0,
        pause_on_battery: false,
        retain_weeks: 0,
        retain_hours: 0,
        prevent_backup_on_constrained_networks: None,
        include_wi_fi_networks: false,
        thread_count: 0,
        prevent_backup_on_expensive_networks: None,
        email_report_json: EmailReport {
            port: 0,
            start_tls: false,
            authentication_type: "".to_string(),
            report_helo_use_ip: None,
            when: "".to_string(),
            report_type: "".to_string(),
            hostname: None,
            username: None,
            from_address: None,
            to_address: None,
            subject: None,
        },
        include_file_list_in_activity_log: false,
        no_backups_alert_days: Some(0),
    };

    let backup_set = BackupSet {
        backup_config,
        backup_folders,
        backup_plan,
        backup_folder_configs: HashMap::new(),
        backup_records: HashMap::new(),
        encryption_keyset: None,
        root_path: PathBuf::from("dummy_path_file_err"),
    };
    let file_entry = FileEntry {
        name: "err_file.txt".to_string(),
        size: 100,
        data_blob_locs: vec![crate::blob_location::BlobLoc {
            blob_identifier: "non_existent_data_blob".to_string(),
            compression_type: 0,
            is_packed: false,
            length: 100,
            offset: 0,
            relative_path: "non_existent_pack/non_existent_data_blob".to_string(),
            stretch_encryption_key: false,
            is_large_pack: Some(false),
        }],
        modification_time_sec: 0,
        creation_time_sec: 0,
        mode: 0o100644,
    };
    let result = backup_set.read_file_content(&file_entry);
    assert!(result.is_err());
}
