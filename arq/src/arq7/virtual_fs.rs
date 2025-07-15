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
