use super::backup_folders::load_json_with_encryption;
use super::encrypted_keyset::EncryptedKeySet;
use crate::error::Result;
use serde::{de::Deserializer, Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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
