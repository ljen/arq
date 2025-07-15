use super::blob_loc::BlobLoc;

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
