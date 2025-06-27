use serde::Deserialize;
use std::collections::HashMap;

// Based on backupconfig.json
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupConfig {
    pub blob_identifier_type: u32,
    pub max_packed_item_length: u64,
    pub backup_name: String,
    #[serde(default)] // isWORM is unused and might be missing
    pub is_worm: bool,
    pub contains_glacier_archives: bool,
    pub additional_unpacked_blob_dirs: Vec<String>,
    pub chunker_version: u32,
    pub computer_name: String,
    pub computer_serial: String, // "unused" in example
    pub blob_storage_class: String, // "unused" in example
    pub is_encrypted: bool,
}

// Based on backupfolders.json
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupFolders {
    pub standard_object_dirs: Vec<String>,
    #[serde(rename = "standardIAObjectDirs", default)] // Explicit rename due to "IA" casing
    pub standard_ia_object_dirs: Vec<String>,
    #[serde(default)]
    pub s3_glacier_object_dirs: Vec<String>,
    #[serde(default)]
    pub onezone_ia_object_dirs: Vec<String>,
    #[serde(default)]
    pub s3_deep_archive_object_dirs: Vec<String>,
    #[serde(default)]
    pub s3_glacier_ir_object_dirs: Vec<String>, // Added based on provided example
    #[serde(default)]
    pub imported_from: Option<String>,
}

// Based on backupfolders/<UUID>/backupfolder.json
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupFolderMeta {
    pub local_path: String,
    pub migrated_from_arq60: bool,
    pub storage_class: String,
    pub disk_identifier: String,
    pub uuid: String,
    pub migrated_from_arq5: bool,
    pub local_mount_point: String,
    pub name: String,
}

// Based on backupplan.json
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupPlan {
    #[serde(rename = "transferRateJSON")] // Corrected to match JSON field name
    pub transfer_rate_json: TransferRateJson,
    pub cpu_usage: u32,
    pub id: u32,
    pub storage_location_id: u32,
    pub excluded_network_interfaces: Vec<String>,
    pub needs_arq5_buckets: bool,
    pub use_buzhash: bool,
    #[serde(default)] // Added default for arq5_use_s3ia
    pub arq5_use_s3ia: bool,
    // #[serde(default)] // Removed default, Option handles absence
    pub object_lock_update_interval_days: Option<u32>, // Changed to Option<u32>
    #[serde(rename = "planUUID")] // Corrected to match JSON field name
    pub plan_uuid: String,
    #[serde(rename = "scheduleJSON")] // Corrected to match JSON field name
    pub schedule_json: ScheduleJson,
    pub keep_deleted_files: bool,
    pub version: u32,
    #[serde(default)]
    pub created_at_pro_console: bool,
    #[serde(default)]
    pub backup_folder_plan_mount_points_are_initialized: bool,
    pub include_new_volumes: bool,
    pub retain_months: u32,
    #[serde(rename = "useAPFSSnapshots")] // Corrected casing
    pub use_apfs_snapshots: bool,
    #[serde(default)]
    pub backup_set_is_initialized: bool,
    #[serde(rename = "backupFolderPlansByUUID")] // Corrected casing
    pub backup_folder_plans_by_uuid: HashMap<String, BackupFolderPlan>,
    pub notify_on_error: bool,
    pub retain_days: u32,
    pub update_time: u64,
    pub excluded_wi_fi_network_names: Vec<String>,
    #[serde(default)]
    pub object_lock_available: bool,
    #[serde(default)]
    pub managed: bool,
    pub name: String,
    pub wake_for_backup: bool,
    pub include_network_interfaces: bool,
    #[serde(default, deserialize_with = "bool_from_int_or_bool::deserialize")]
    pub dataless_files_option: bool, // Changed from u32 to bool and added custom deserializer
    pub retain_all: bool,
    pub is_encrypted: bool,
    pub active: bool,
    pub notify_on_success: bool,
    pub prevent_sleep: bool,
    pub creation_time: u64,
    pub pause_on_battery: bool,
    pub retain_weeks: u32,
    pub retain_hours: u32,
    #[serde(default)]
    pub prevent_backup_on_constrained_networks: bool,
    pub include_wi_fi_networks: bool,
    pub thread_count: u32,
    #[serde(default)]
    pub prevent_backup_on_expensive_networks: bool,
    #[serde(rename = "emailReportJSON")] // Corrected casing
    pub email_report_json: EmailReportJson,
    pub include_file_list_in_activity_log: bool,
    pub no_backups_alert_days: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferRateJson {
    pub enabled: bool,
    pub start_time_of_day: String,
    pub days_of_week: Vec<String>,
    pub schedule_type: String,
    pub end_time_of_day: String,
    #[serde(default)]
    pub max_kbps: u64, // Not in all examples, but present in documentation
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleJson {
    #[serde(default)]
    pub back_up_and_validate: bool, // Not in all examples
    pub start_when_volume_is_connected: bool,
    pub pause_during_window: bool,
    #[serde(rename = "type")]
    pub schedule_type: String, // "type" is a reserved keyword in Rust
    #[serde(default)]
    pub days_of_week: Vec<String>, // Not in "Manual" type
    #[serde(default)]
    pub every_hours: u32, // Not in "Manual" type
    #[serde(default)]
    pub minutes_after_hour: u32, // Not in "Manual" type
    #[serde(default)]
    pub pause_from: String, // Not in "Manual" type
    #[serde(default)]
    pub pause_to: String, // Not in "Manual" type
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupFolderPlan {
    #[serde(rename = "backupFolderUUID")] // Corrected casing
    pub backup_folder_uuid: String,
    pub disk_identifier: String,
    pub blob_storage_class: String,
    pub ignored_relative_paths: Vec<String>,
    pub skip_if_not_mounted: bool,
    pub skip_during_backup: bool,
    pub use_disk_identifier: bool,
    pub relative_path: String,
    pub wildcard_excludes: Vec<String>,
    pub excluded_drives: Vec<String>,
    pub local_path: String,
    pub all_drives: bool,
    #[serde(default)] // Not in all examples
    pub skip_tm_excludes: bool,
    pub regex_excludes: Vec<String>,
    pub name: String,
    pub local_mount_point: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EmailReportJson {
    pub port: u32,
    #[serde(rename = "startTLS")] // Corrected Casing
    pub start_tls: bool,
    pub authentication_type: String,
    #[serde(default)] // Not in all examples
    pub report_helou_se_ip: Option<bool>, // reportHELOUseIP
     #[serde(default)]
    pub from_address: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub to_address: Option<String>,
    #[serde(rename = "type")]
    pub email_type: String, // "type" is a reserved keyword
    #[serde(default)]
    pub username: Option<String>,
    pub when: String,
}

// Based on documentation for BlobLoc
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlobLoc {
    pub blob_identifier: String, // SHA256 hex string for new data
    pub is_packed: bool,
    pub relative_path: String, // Path to .pack file or object path
    pub offset: u64,
    pub length: u64,
    pub stretch_encryption_key: bool, // Always true for new data
    pub compression_type: u32, // 2 for LZ4 for new data
}

// Based on documentation for Node (binary format, this is for the JSON part in BackupRecord)
// The actual binary Node will need a different parser.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo { // Renamed to NodeInfo to avoid conflict with binary Node
    #[serde(default, rename = "changeTime_nsec")]
    pub change_time_nsec: i64,
    #[serde(default, rename = "changeTime_sec")]
    pub change_time_sec: i64,
    #[serde(default)]
    pub computer_os_type: Option<u32>, // Not always present
    #[serde(default)]
    pub contained_files_count: Option<u64>, // For directories
    #[serde(default, rename = "creationTime_nsec")]
    pub creation_time_nsec: i64,
    #[serde(default, rename = "creationTime_sec")]
    pub creation_time_sec: i64,
    #[serde(default, deserialize_with = "deserialize_empty_vec_or_values")]
    pub data_blob_locs: Vec<BlobLoc>, // For files
    #[serde(default)]
    pub deleted: Option<bool>,
    #[serde(default)]
    pub is_tree: Option<bool>, // Key to differentiate file/directory in some contexts
    #[serde(default)]
    pub item_size: Option<u64>,
    #[serde(default, rename = "mac_st_dev")]
    pub mac_st_dev: Option<i32>,
    #[serde(default, rename = "mac_st_flags")]
    pub mac_st_flags: Option<i32>, // This is u_int from stat.h, so u32 might be better
    #[serde(default, rename = "mac_st_gid")]
    pub mac_st_gid: Option<u32>,
    #[serde(default, rename = "mac_st_ino")]
    pub mac_st_ino: Option<u64>,
    #[serde(default, rename = "mac_st_mode")]
    pub mac_st_mode: Option<u32>, // This is mode_t, typically u16 or u32
    #[serde(default, rename = "mac_st_nlink")]
    pub mac_st_nlink: Option<u32>, // This is nlink_t
    #[serde(default, rename = "mac_st_rdev")]
    pub mac_st_rdev: Option<i32>, // This is dev_t
    #[serde(default, rename = "mac_st_uid")]
    pub mac_st_uid: Option<u32>,
    #[serde(default, rename = "modificationTime_nsec")]
    pub modification_time_nsec: i64,
    #[serde(default, rename = "modificationTime_sec")]
    pub modification_time_sec: i64,
    #[serde(default)]
    pub tree_blob_loc: Option<BlobLoc>, // For directories
    #[serde(default)]
    pub win_attrs: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_empty_vec_or_values")]
    pub xattrs_blob_locs: Vec<BlobLoc>,
    // Fields from Arq5 commit/node if applicable
    #[serde(default)]
    pub arq5_tree_blob_key: Option<Arq5BlobKey>,
}

fn deserialize_empty_vec_or_values<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Helper<V> {
        Empty,
        Values(Vec<V>),
    }

    match Helper::<T>::deserialize(deserializer)? {
        Helper::Empty => Ok(Vec::new()),
        Helper::Values(v) => Ok(v),
    }
}

// Helper for deserializing Option<bool> from various JSON types (null, bool, int, string)
mod opt_bool_from_int_or_bool {
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Val {
            Null,
            Bool(bool),
            Int(i64), // Use i64 to catch potential negative numbers if they ever appear
            Str(String),
        }

        match Val::deserialize(deserializer)? {
            Val::Null => Ok(None),
            Val::Bool(b) => Ok(Some(b)),
            Val::Int(i) => Ok(Some(i != 0)),
            Val::Str(s) => {
                match s.to_lowercase().as_str() {
                    "true" | "1" => Ok(Some(true)),
                    "false" | "0" => Ok(Some(false)),
                    _ => Err(serde::de::Error::custom(format!("expected Option<bool> parsable from string, got \"{}\"", s)))
                }
            }
        }
    }
}

// Helper for deserializing fields that might be boolean or numeric (0/1) into bool
mod bool_from_int_or_bool {
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BoolOrInt {
            Bool(bool),
            Int(u32),
            Str(String),
        }

        match BoolOrInt::deserialize(deserializer)? {
            BoolOrInt::Bool(b) => Ok(b),
            BoolOrInt::Int(i) => Ok(i != 0),
            BoolOrInt::Str(s) => {
                match s.to_lowercase().as_str() {
                    "true" | "1" => Ok(true),
                    "false" | "0" => Ok(false),
                    _ => Err(serde::de::Error::custom(format!("expected boolean or 0/1, got string \"{}\"", s)))
                }
            }
        }
    }
}


// Based on documentation for Arq5 BlobKey (used in BackupRecord for Arq5 data)
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Arq5BlobKey {
    pub archive_size: Option<u64>, // May not always be present
    pub compression_type: u32,
    pub sha1: String,
    pub storage_type: u32,
    pub stretch_encryption_key: bool,
}


// Based on backup record file (JSON part)
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupRecord {
    #[serde(default, deserialize_with = "opt_bool_from_int_or_bool::deserialize")]
    pub archived: Option<bool>, // Changed to Option<bool>
    pub arq_version: String,
    #[serde(rename = "backupFolderUUID")] // Corrected casing
    pub backup_folder_uuid: String,
    #[serde(rename = "backupPlanJSON")] // Corrected casing
    pub backup_plan_json: BackupPlan, // Reverted to BackupPlan
    #[serde(rename = "backupPlanUUID")] // Assuming this might also have UUID casing
    pub backup_plan_uuid: String,
    #[serde(default)]
    pub computer_os_type: Option<u32>, // Not always present
    #[serde(default, deserialize_with = "opt_bool_from_int_or_bool::deserialize")]
    pub copied_from_commit: Option<bool>, // Changed to Option<bool>
    #[serde(default, deserialize_with = "opt_bool_from_int_or_bool::deserialize")]
    pub copied_from_snapshot: Option<bool>, // Changed to Option<bool>
    pub creation_date: u64, // Timestamp
    #[serde(default)]
    pub disk_identifier: Option<String>, // Not always present
    #[serde(default)] // Added default for error_count
    pub error_count: u32,
    #[serde(deserialize_with = "bool_from_int_or_bool::deserialize")]
    pub is_complete: bool, // Changed from u32, using helper
    #[serde(default)]
    pub local_mount_point: Option<String>, // Not always present
    #[serde(default)]
    pub local_path: Option<String>, // Not always present
    pub node: NodeInfo, // The root Node of the file tree
    pub relative_path: String, // Path to this backuprecord file
    pub storage_class: String,
    pub version: u32,
    #[serde(default)]
    pub volume_name: Option<String>, // Not always present
    // Fields for Arq5 imported records
    #[serde(default)]
    pub arq5_bucket_xml: Option<String>,
    #[serde(default)]
    pub arq5_tree_blob_key: Option<Arq5BlobKey>,
}

// Binary Tree structure (to be parsed from treepacks)
// This will require a custom deserializer or manual parsing logic
#[derive(Debug)]
pub struct Tree {
    pub version: u32,
    pub child_nodes_by_name: HashMap<String, Node>, // Name -> Node
}

// Binary Node structure (to be parsed from treepacks or as part of a Tree)
// This will require a custom deserializer or manual parsing logic
#[derive(Debug, Clone)]
pub struct Node {
    pub is_tree: bool,
    pub tree_blob_loc: Option<BlobLoc>, // Present if is_tree is true
    pub computer_os_type: u32,
    pub data_blob_locs: Vec<BlobLoc>,
    pub acl_blob_loc_is_not_nil: bool,
    pub acl_blob_loc: Option<BlobLoc>, // Present if acl_blob_loc_is_not_nil is true
    pub xattrs_blob_locs: Vec<BlobLoc>,
    pub item_size: u64,
    pub contained_files_count: u64, // For directories
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub create_time_sec: i64,
    pub create_time_nsec: i64,
    pub username: String,
    pub group_name: String,
    pub deleted: bool,
    pub mac_st_dev: i32,
    pub mac_st_ino: u64,
    pub mac_st_mode: u32,
    pub mac_st_nlink: u32,
    pub mac_st_uid: u32,
    pub mac_st_gid: u32,
    pub mac_st_rdev: i32,
    pub mac_st_flags: i32, // This is u_int from stat.h
    pub win_attrs: u32,
    pub win_reparse_tag: Option<u32>, // if Tree version >= 2
    pub win_reparse_point_is_directory: Option<bool>, // if Tree version >= 2
}
