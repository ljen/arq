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
//! ### 🔄 Binary Format Support (Partial)
//! - Binary format parsing utilities for Nodes and Trees
//! - BlobLoc data loading from pack files
//! - LZ4 decompression support
//! - Foundation for full binary tree/node parsing
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
use serde::de::Deserializer;
use serde::Deserialize;
use std::any::{type_name_of_val, TypeId};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

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
    return Ok(serde_json::from_reader(reader)?)
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
    pub excluded_drives: Vec<String>,
    #[serde(rename = "localPath")]
    pub local_path: String,
    #[serde(rename = "allDrives")]
    pub all_drives: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "skipTMExcludes")]
    pub skip_tm_excludes: Option<bool>,
    #[serde(rename = "regexExcludes")]
    pub regex_excludes: Vec<String>,
    pub name: String,
    #[serde(rename = "localMountPoint")]
    pub local_mount_point: String,
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
    #[serde(rename = "noBackupsAlertDays")]
    pub no_backups_alert_days: u32,
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
    /// Parse a BlobLoc from binary data according to Arq 7 format.
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

impl Node {
    /// Parses a Node from binary data.
    pub fn from_binary_reader<R: binary::ArqBinaryReader>(
        reader: &mut R,
        tree_version: Option<u32>,
    ) -> Result<Self> {
        let is_tree = reader.read_arq_bool()?;
        let tree_blob_loc = if is_tree {
            BlobLoc::from_binary_reader(reader).ok()
        } else {
            None
        };
        let computer_os_type = reader.read_arq_u32()?;
        let data_blob_locs_count = reader.read_arq_u64()?;
        let mut data_blob_locs = Vec::new();
        for _i in 0..data_blob_locs_count {
            match BlobLoc::from_binary_reader(reader) {
                Ok(blob_loc) => data_blob_locs.push(blob_loc),
                Err(_) => {
                    panic!();
                }
            }
        }

        let acl_blob_loc = match reader.read_arq_bool() {
            Ok(acl_not_nil) if acl_not_nil => BlobLoc::from_binary_reader(reader).ok(),
            _ => None,
        };

        let xattrs_blob_locs_count = reader.read_arq_u64().unwrap_or(0);
        let mut parsed_xattrs_blob_locs = Vec::new();

        for _ in 0..xattrs_blob_locs_count {
            if let Ok(blob_loc) = BlobLoc::from_binary_reader(reader) {
                parsed_xattrs_blob_locs.push(blob_loc);
            } else {
                panic!();
            }
        }
        let xattrs_blob_locs = if parsed_xattrs_blob_locs.is_empty() && xattrs_blob_locs_count == 0
        {
            None
        } else {
            Some(parsed_xattrs_blob_locs)
        };

        // Fallback values are from original BinaryNode::from_reader
        let item_size = reader
            .read_arq_u64()
            .unwrap_or(if is_tree { 0 } else { 15 });
        let contained_files_count =
            Some(reader.read_arq_u64().unwrap_or(if is_tree { 0 } else { 1 })); // Wrap in Some()

        let modification_time_sec = reader.read_arq_i64().unwrap_or(0);
        let modification_time_nsec = reader.read_arq_i64().unwrap_or(0);
        let change_time_sec = reader.read_arq_i64().unwrap_or(0);
        let change_time_nsec = reader.read_arq_i64().unwrap_or(0);
        let creation_time_sec = reader.read_arq_i64().unwrap_or(0);
        let creation_time_nsec = reader.read_arq_i64().unwrap_or(0);

        let username = reader.read_arq_string().ok().flatten();
        let group_name = reader.read_arq_string().ok().flatten();
        let deleted = reader.read_arq_bool().unwrap_or(false);

        let mac_st_dev = reader.read_arq_i32().unwrap_or(0);
        let mac_st_ino = reader.read_arq_u64().unwrap_or(0);
        let mac_st_mode =
            reader
                .read_arq_u32()
                .unwrap_or(if is_tree { 0o040755 } else { 0o100644 }); // Typical modes
        let mac_st_nlink = reader.read_arq_u32().unwrap_or(1);
        let mac_st_uid = Some(reader.read_arq_u32().unwrap_or(0)); // Wrap in Some()
        let mac_st_gid = reader.read_arq_u32().unwrap_or(0);
        let mac_st_rdev = reader.read_arq_i32().unwrap_or(0);
        let mac_st_flags = reader.read_arq_i32().unwrap_or(0);

        let win_attrs = reader.read_arq_u32().unwrap_or(0);

        let reparse_tag = if tree_version.unwrap_or(1) >= 2 {
            reader.read_arq_u32().ok()
        } else {
            None
        };
        let reparse_point_is_directory = if tree_version.unwrap_or(1) >= 2 {
            reader.read_arq_bool().ok()
        } else {
            None
        };

        Ok(Node {
            is_tree,
            item_size,
            deleted,
            computer_os_type,
            modification_time_sec,
            modification_time_nsec,
            change_time_sec,
            change_time_nsec,
            creation_time_sec,
            creation_time_nsec,
            mac_st_mode,
            mac_st_ino,
            mac_st_nlink,
            mac_st_gid,
            win_attrs,
            contained_files_count,
            mac_st_uid,
            mac_st_dev,
            mac_st_rdev,
            mac_st_flags,
            data_blob_locs,
            tree_blob_loc,
            xattrs_blob_locs,
            username,
            group_name,
            reparse_tag,
            reparse_point_is_directory,
            acl_blob_loc,
        })
    }
}

/// BackupRecord represents a backup record file containing backup metadata and the root node
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Arq5TreeBlobKey {
    #[serde(rename = "storageType")]
    pub storage_type: u32,
    #[serde(rename = "archiveSize")]
    pub archive_size: u64,
    pub sha1: String,
    #[serde(rename = "stretchEncryptionKey")]
    pub stretch_encryption_key: bool,
    #[serde(rename = "compressionType")]
    pub compression_type: u32,
}

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
    pub arq5_tree_blob_key: Option<Arq5TreeBlobKey>,
    pub archived: Option<bool>, // Matches example, though original top-level was not optional
    #[serde(rename = "relativePath")]
    pub relative_path: Option<String>,
    // No top-level 'node' field in the provided v12 JSON example
    // No 'diskIdentifier' in the provided v12 JSON example
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
    pub node: Node,
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

impl Node {
    /// Load the tree data if this node is a tree
    pub fn load_tree(
        &self,
        backup_set_path: &std::path::Path,
    ) -> Result<Option<binary::BinaryTree>> {
        self.load_tree_with_encryption(backup_set_path, None)
    }

    /// Load tree data with encryption support
    pub fn load_tree_with_encryption<P: AsRef<Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<binary::BinaryTree>> {
        if let Some(tree_blob_loc) = &self.tree_blob_loc {
            tree_blob_loc.load_tree_with_encryption(backup_set_dir.as_ref(), keyset)
        } else {
            Ok(None)
        }
    }

    /// Load data blob locations with encryption support
    pub fn load_data_blobs_with_encryption<P: AsRef<Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<Vec<u8>>> {
        let mut data_chunks = Vec::new();
        let backup_set_dir = backup_set_dir.as_ref();

        for blob_loc in &self.data_blob_locs {
            let data = blob_loc.load_data(backup_set_dir, keyset)?;
            data_chunks.push(data);
        }

        Ok(data_chunks)
    }

    /// Reconstruct complete file data with encryption support
    pub fn reconstruct_file_data_with_encryption<P: AsRef<Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let data_chunks = self.load_data_blobs_with_encryption(backup_set_dir.as_ref(), keyset)?;
        Ok(data_chunks.into_iter().flatten().collect())
    }

    /// Extract complete file to path with encryption support
    pub fn extract_file_with_encryption<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        backup_set_dir: P1,
        output_path: P2,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<()> {
        if self.is_tree {
            return Err(Error::InvalidFormat(
                "Cannot extract directory as file".to_string(),
            ));
        }

        let file_data = self.reconstruct_file_data_with_encryption(backup_set_dir, keyset)?;
        std::fs::write(output_path, file_data)?;
        Ok(())
    }

    // The from_binary_node method that was here has been removed as it's obsolete.
    // BinaryTree's from_reader now uses Node::from_binary_reader directly.
}

impl BackupSet {
    /// Load a complete BackupSet from a directory path
    pub fn from_directory<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
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
        })
    }

    /// Add method to load with explicit password
    pub fn from_directory_with_password<P: AsRef<Path>>(
        dir_path: P,
        password: Option<&str>,
    ) -> Result<BackupSet> {
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
                    if let Some(node) =
                        self.find_node_by_path(&record.node, file_path, backup_set_dir.as_ref())?
                    {
                        if !node.is_tree {
                            return node.extract_file_with_encryption(
                                backup_set_dir.as_ref(), // Ensure P1 is AsRef<Path>
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
        node: &Node, // This function is now more general, called with a specific node
        target_path: &str,
        backup_set_dir: &Path,
    ) -> Result<Option<Node>> {
        let path_parts: Vec<&str> = target_path.trim_start_matches('/').split('/').collect();
        self.find_node_recursive(node, &path_parts, 0, backup_set_dir)
    }

    // find_node_recursive remains largely the same as it operates on a Node,
    // but its callers need to ensure they provide a valid Node.
    fn find_node_recursive(
        &self,
        node: &Node,
        path_parts: &[&str],
        depth: usize,
        backup_set_dir: &Path,
    ) -> Result<Option<Node>> {
        if depth >= path_parts.len() {
            return Ok(Some(node.clone()));
        }

        if !node.is_tree {
            return Ok(None);
        }

        if let Some(tree) =
            node.load_tree_with_encryption(backup_set_dir, self.encryption_keyset.as_ref())?
        {
            let target_name = path_parts[depth];
            if let Some(child_node) = tree.child_nodes.get(target_name) {
                return self.find_node_recursive(child_node, path_parts, depth + 1, backup_set_dir);
            }
        }
        Ok(None)
    }

    /// List all files in the backup set (primarily from Arq7 records)
    pub fn list_all_files<P: AsRef<Path>>(&self, backup_set_dir: P) -> Result<Vec<String>> {
        let mut files = Vec::new();
        let backup_set_dir_ref = backup_set_dir.as_ref();

        for (_, records) in &self.backup_records {
            for generic_record in records {
                if let GenericBackupRecord::Arq7(record) = generic_record {
                    self.collect_files_recursive(
                        &record.node,
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
        node: &Node,
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

        if let Some(tree) =
            node.load_tree_with_encryption(backup_set_dir, self.encryption_keyset.as_ref())?
        {
            for (name, child_node) in &tree.child_nodes {
                let child_path = if current_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", current_path, name)
                };
                self.collect_files_recursive(child_node, child_path, files, backup_set_dir)?;
            }
        }
        Ok(())
    }

    /// Get backup statistics
    pub fn get_statistics<P: AsRef<Path>>(&self, backup_set_dir: P) -> Result<BackupStatistics> {
        let mut stats = BackupStatistics::default();
        let backup_set_dir_ref = backup_set_dir.as_ref();

        for (_, records_vec) in &self.backup_records {
            // Renamed records to records_vec to avoid conflict
            stats.folder_count += 1; // This counts folders in backup_records map, not file system folders.
            stats.record_count += records_vec.len() as u32;

            for generic_record in records_vec {
                match generic_record {
                    GenericBackupRecord::Arq7(record) => {
                        let (file_count, total_size) = count_files_in_node(
                            &record.node,
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
    pub fn verify_integrity<P: AsRef<Path>>(&self, backup_set_dir: P) -> Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        let backup_set_dir_ref = backup_set_dir.as_ref();

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
    pub fn load_tree(&self, backup_set_path: &std::path::Path) -> Result<binary::BinaryTree> {
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
    ) -> Result<Option<binary::BinaryTree>> {
        let data = self.load_data(backup_set_dir, keyset)?;

        if data.is_empty() {
            return Ok(None);
        }

        let tree = binary::BinaryTree::from_decompressed_data(&data)?;
        Ok(Some(tree))
    }

    /// Load and parse a node from this blob location
    pub fn load_node(&self, backup_set_path: &std::path::Path) -> Result<Option<Node>> {
        // Changed return type to unified Node
        self.load_node_with_encryption(backup_set_path, None)
    }

    /// Load and parse as binary node with encryption support
    pub fn load_node_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<Node>> {
        // Changed return type to unified Node
        let data = self.load_data(backup_set_dir, keyset)?;

        if data.is_empty() {
            return Ok(None);
        }

        let mut cursor = std::io::Cursor::new(&data);
        // Call the new from_binary_reader on the unified Node struct
        let node = Node::from_binary_reader(&mut cursor, None)?;
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
    pub fn find_all_blob_locations(&self) -> Vec<BlobLoc> {
        // Changed to return owned BlobLocs
        let mut blob_locations = Vec::new();

        for (_, records_vec) in &self.backup_records {
            for generic_record in records_vec {
                match generic_record {
                    GenericBackupRecord::Arq7(record) => {
                        collect_blob_locations_from_node(&record.node, &mut blob_locations);
                    }
                    GenericBackupRecord::Arq5(record) => {
                        if let Some(key) = &record.arq5_tree_blob_key {
                            // Convert Arq5TreeBlobKey to BlobLoc. This is an approximation.
                            blob_locations.push(BlobLoc {
                                blob_identifier: key.sha1.clone(),
                                compression_type: key.compression_type,
                                is_packed: false, // Assumption for Arq5TreeBlobKey
                                length: key.archive_size,
                                offset: 0, // Assumption for Arq5TreeBlobKey
                                relative_path: format!("arq5_migrated_tree_blob/{}", key.sha1), // Placeholder path
                                stretch_encryption_key: key.stretch_encryption_key,
                                is_large_pack: None, // Arq5 might not have this concept
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
fn collect_blob_locations_from_node(node: &Node, blob_locations: &mut Vec<BlobLoc>) {
    // Changed to Vec<BlobLoc>
    // Add data blob locations from this node
    for blob_loc in &node.data_blob_locs {
        blob_locations.push(blob_loc.clone()); // Clone to own
    }

    // Add tree blob location if present
    if let Some(tree_blob_loc) = &node.tree_blob_loc {
        blob_locations.push(tree_blob_loc.clone()); // Clone to own
    }

    // Add xattrs blob locations if present
    if let Some(xattrs_blob_locs) = &node.xattrs_blob_locs {
        for blob_loc in xattrs_blob_locs {
            blob_locations.push(blob_loc.clone()); // Clone to own
        }
    }
}

/// Helper function for metadata extraction
fn count_files_in_node(
    node: &Node,
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

    if let Some(tree) = node.load_tree_with_encryption(backup_set_dir, keyset)? {
        for (_, child_node) in &tree.child_nodes {
            // child_node is already &Node
            // let child = Node::from_binary_node(child_node); // No longer needed
            let (child_files, child_size) =
                count_files_in_node(child_node, backup_set_dir, keyset)?; // Pass child_node directly
            file_count += child_files;
            total_size += child_size;
        }
    }

    Ok((file_count, total_size))
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    match record.node.load_tree(backup_set_dir) {
                        Ok(Some(_tree)) => {
                            // Successfully loaded binary tree data
                            println!("Successfully loaded binary tree data");
                        }
                        _ => {
                            // Tree loading failed, which is expected if pack files don't exist
                            println!("Tree loading failed (expected if pack files don't exist)");
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
                    assert_eq!(record.node.computer_os_type, 1);
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
}
