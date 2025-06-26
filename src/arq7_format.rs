use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, BufReader};
use std::fs::File;
use std::path::Path;

use crate::error::{Result, Error};
use crate::type_utils::ArqRead; // For binary parsing helpers, may need to extend

// For EncryptedKeySet decryption
use ring::{pbkdf2, digest};
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes::cipher::block_padding::Pkcs7; // Arq uses PKCS7 padding

// Define Decryptor for AES-256-CBC
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;


// Enum for blobIdentifierType in backupconfig.json
#[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum BlobIdentifierType {
    Sha1 = 1,
    Sha256 = 2,
}

// Struct for backupconfig.json
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupConfig {
    pub blob_identifier_type: BlobIdentifierType,
    pub max_packed_item_length: u64,
    pub backup_name: String,
    #[serde(rename = "isWORM")]
    pub is_worm: bool, // unused
    pub contains_glacier_archives: bool,
    pub additional_unpacked_blob_dirs: Vec<String>,
    pub chunker_version: u32,
    pub computer_name: String,
    pub computer_serial: String, // unused
    pub blob_storage_class: String, // unused
    pub is_encrypted: bool,
}

// Struct for backupfolders.json
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupFolders {
    pub standard_object_dirs: Vec<String>,
    #[serde(default)]
    pub standard_ia_object_dirs: Vec<String>,
    #[serde(default)]
    pub onezone_ia_object_dirs: Vec<String>,
    #[serde(default)]
    pub s3_glacier_object_dirs: Vec<String>,
    #[serde(default)]
    pub s3_deep_archive_object_dirs: Vec<String>,
    #[serde(default)]
    pub imported_from: Option<String>,
}

// Struct for backupfolders/<UUID>/backupfolder.json
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupFolder {
    pub local_path: String,
    #[serde(default)]
    pub migrated_from_arq60: bool,
    pub storage_class: String, //TODO: Potentially an enum "STANDARD", etc.
    pub disk_identifier: String,
    pub uuid: String,
    #[serde(default)]
    pub migrated_from_arq5: bool,
    pub local_mount_point: String,
    pub name: String,
}

// Struct for BlobLoc
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlobLoc {
    pub blob_identifier: String,
    pub is_packed: bool,
    pub relative_path: String,
    pub offset: u64,
    pub length: u64,
    pub stretch_encryption_key: bool,
    pub compression_type: u32, // 0=none, 1=Gzip, 2=LZ4
}

// Struct for Node in a backup record or a Tree
// Based on JSON representation in backup record and binary format
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NodeJson {
    #[serde(rename = "changeTime_nsec")]
    pub change_time_nsec: i64,
    #[serde(rename = "changeTime_sec")]
    pub change_time_sec: i64,
    #[serde(default)]
    pub computer_os_type: Option<u32>, // Present in JSON, also in binary
    #[serde(default)]
    pub contained_files_count: Option<u64>, // Present in JSON, also in binary
    #[serde(rename = "creationTime_nsec")]
    pub creation_time_nsec: i64,
    #[serde(rename = "creationTime_sec")]
    pub creation_time_sec: i64,
    #[serde(default)]
    pub data_blob_locs: Vec<BlobLoc>, // Present in JSON, also in binary
    #[serde(default)]
    pub deleted: Option<bool>, // Present in JSON, also in binary
    pub is_tree: bool, // Present in JSON, also in binary
    pub item_size: u64, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_dev")]
    pub mac_st_dev: Option<i32>, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_flags")]
    pub mac_st_flags: Option<i32>, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_gid")]
    pub mac_st_gid: Option<u32>, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_ino")]
    pub mac_st_ino: Option<u64>, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_mode")]
    pub mac_st_mode: Option<u32>, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_nlink")]
    pub mac_st_nlink: Option<u32>, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_rdev")]
    pub mac_st_rdev: Option<i32>, // Present in JSON, also in binary
    #[serde(default, rename = "mac_st_uid")]
    pub mac_st_uid: Option<u32>, // Present in JSON, also in binary
    #[serde(rename = "modificationTime_nsec")]
    pub modification_time_nsec: i64,
    #[serde(rename = "modificationTime_sec")]
    pub modification_time_sec: i64,
    #[serde(default)]
    pub tree_blob_loc: Option<BlobLoc>, // Present in JSON, also in binary
    #[serde(default, rename = "winAttrs")]
    pub win_attrs: Option<u32>, // Present in JSON, also in binary
    #[serde(default)]
    pub xattrs_blob_locs: Vec<BlobLoc>, // Present in JSON
    // Binary only fields, not in JSON node representation directly, but needed for parsing binary Node
    // username: String, (Binary only)
    // groupName: String, (Binary only)
    // aclBlobLocIsNotNil: bool, (Binary only)
    // aclBlobLoc: Option<BlobLoc>, (Binary only)
    // win_reparse_tag: u32, (Binary only, if Tree version >= 2)
    // win_reparse_point_is_directory: bool, (Binary only, if Tree version >= 2)
}

impl BackupConfig {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let config = serde_json::from_reader(reader)
            .map_err(|e| Error::JsonDecode(format!("Failed to parse BackupConfig: {}", e)))?;
        Ok(config)
    }
}

impl BackupFolders {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let folders = serde_json::from_reader(reader)
            .map_err(|e| Error::JsonDecode(format!("Failed to parse BackupFolders: {}", e)))?;
        Ok(folders)
    }
}

impl BackupFolder {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let folder = serde_json::from_reader(reader)
            .map_err(|e| Error::JsonDecode(format!("Failed to parse BackupFolder: {}", e)))?;
        Ok(folder)
    }
}


// Struct for Arq 5 TreeBlobKey (found in backup records migrated from Arq 5)
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Arq5TreeBlobKey {
    pub archive_size: u64,
    pub compression_type: u32,
    pub sha1: String,
    pub storage_type: u32,
    pub stretch_encryption_key: bool,
}

// Struct for the `backupPlanJSON` field within a BackupRecord
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupPlanJson {
    pub active: u8, // bool?
    // there are many more fields, this is just a placeholder
    // For now, we might not need to parse all of them in detail
    // depending on the library's goals.
    // We'll add more as needed.
    pub name: String,
    pub plan_uuid: String,
    pub is_encrypted: bool,
    #[serde(default)]
    pub backup_folder_plans_by_uuid: BTreeMap<String, BackupFolderPlanJson>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupFolderPlanJson {
    pub backup_folder_uuid: String,
    pub local_path: String,
    pub name: String,
    // other fields as necessary
}


// Struct for backup record files (e.g., 00161/4294169.backuprecord)
// This is a Plist format, but the example shows a JSON-like structure.
// Assuming it's JSON for now based on the documentation's presentation.
// If it's truly Plist, we'll need a Plist parser.
// The documentation mentions "The file is stored LZ4-compressed and (optionally) encrypted."
// And then shows a JSON example. Let's assume JSON that might be inside a Plist, or just JSON.
// For now, let's treat the content as JSON.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupRecord {
    pub archived: u8, // bool?
    pub arq_version: String,
    pub backup_folder_uuid: String,
    pub backup_plan_json: BackupPlanJson,
    pub backup_plan_uuid: String,
    #[serde(default)]
    pub computer_os_type: Option<u32>,
    #[serde(default)]
    pub copied_from_commit: bool, // Important for Arq5 migrated data
    #[serde(default)]
    pub copied_from_snapshot: bool,
    pub creation_date: i64, // Unix timestamp
    #[serde(default)]
    pub disk_identifier: Option<String>,
    #[serde(default)]
    pub error_count: u64,
    #[serde(rename = "isComplete")]
    pub is_complete: bool,
    #[serde(default)]
    pub local_mount_point: Option<String>,
    pub local_path: String,
    pub node: Option<NodeJson>, // Root node of the backup
    pub relative_path: String,
    pub storage_class: String, // TODO: Enum?
    pub version: u32, // e.g. 100 for Arq 7, 12 for Arq 5 migrated
    #[serde(default)]
    pub volume_name: Option<String>,

    // Fields for Arq 5 migrated data
    #[serde(rename = "arq5BucketXML")]
    pub arq5_bucket_xml: Option<String>,
    #[serde(rename = "arq5TreeBlobKey")]
    pub arq5_tree_blob_key: Option<Arq5TreeBlobKey>,
}


// Binary Tree structure
// Stored LZ4-compressed and (optionally) encrypted in "treepacks"
// This struct is for the actual binary data, not the JSON representation.
use crate::compression::lz4_decompress_with_prefix; // Assuming this handles the 4-byte prefix
use crate::plist; // For parsing the actual BackupRecord content

// We will need a separate parser for this.
pub struct Tree {
    pub version: u32,
    // pub child_nodes_by_name: BTreeMap<String, NodeBin>, // NodeBin would be the binary Node structure
}

// Struct for Arq 7's "Encrypted Object" format (ARQO header)
// This is similar to the existing object_encryption::EncryptedObject but uses keys from EncryptedKeySetPlaintext
#[derive(Debug)]
struct Arq7EncryptedObject {
    hmac_sha256: Vec<u8>, // 32 bytes
    master_iv: Vec<u8>, // 16 bytes
    encrypted_data_iv_session_key: Vec<u8>, // 64 bytes
    ciphertext: Vec<u8>, // rest of the data
}

impl Arq7EncryptedObject {
    const HEADER: &'static [u8] = b"ARQO";
    const HMAC_LEN: usize = 32;
    const MASTER_IV_LEN: usize = 16;
    const ENC_DATA_IV_SESSION_KEY_LEN: usize = 64;

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if !data.starts_with(Self::HEADER) {
            return Err(Error::InvalidData("Arq7EncryptedObject missing ARQO header".into()));
        }
        let mut offset = Self::HEADER.len();

        if data.len() < offset + Self::HMAC_LEN {
            return Err(Error::InvalidData("Arq7EncryptedObject too short for HMAC".into()));
        }
        let hmac_sha256 = data[offset..offset + Self::HMAC_LEN].to_vec();
        offset += Self::HMAC_LEN;

        if data.len() < offset + Self::MASTER_IV_LEN {
            return Err(Error::InvalidData("Arq7EncryptedObject too short for master IV".into()));
        }
        let master_iv = data[offset..offset + Self::MASTER_IV_LEN].to_vec();
        offset += Self::MASTER_IV_LEN;

        if data.len() < offset + Self::ENC_DATA_IV_SESSION_KEY_LEN {
            return Err(Error::InvalidData("Arq7EncryptedObject too short for encrypted data IV + session key".into()));
        }
        let encrypted_data_iv_session_key = data[offset..offset + Self::ENC_DATA_IV_SESSION_KEY_LEN].to_vec();
        offset += Self::ENC_DATA_IV_SESSION_KEY_LEN;

        let ciphertext = data[offset..].to_vec();

        Ok(Arq7EncryptedObject {
            hmac_sha256,
            master_iv,
            encrypted_data_iv_session_key,
            ciphertext,
        })
    }

    // Decrypts the object using keys from EncryptedKeySetPlaintext
    fn decrypt(&self, keys: &EncryptedKeySetPlaintext) -> Result<Vec<u8>> {
        // 1. Verify HMAC-SHA256
        // HMAC is of (master IV + "encrypted data IV + session key" + ciphertext)
        // using the second "master key" (which is `keys.hmac_key` from encryptedkeyset.dat's plaintext)
        let mut data_to_hmac = Vec::new();
        data_to_hmac.extend_from_slice(&self.master_iv);
        data_to_hmac.extend_from_slice(&self.encrypted_data_iv_session_key);
        data_to_hmac.extend_from_slice(&self.ciphertext);

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&keys.hmac_key)
            .map_err(|_| Error::Encryption("Failed to initialize HMAC for Arq7EncryptedObject".into()))?;
        mac.update(&data_to_hmac);
        let calculated_hmac = mac.finalize().into_bytes();

        if calculated_hmac[..] != self.hmac_sha256[..] {
            return Err(Error::Encryption("Arq7EncryptedObject HMAC mismatch".into()));
        }

        // 2. Decrypt "encrypted data IV + session key"
        // using the first "master key" (`keys.encryption_key`) and "master IV"
        let mut enc_data_iv_session_clone = self.encrypted_data_iv_session_key.clone();
        let data_iv_session_key_plaintext = Aes256CbcDec::new_from_slices(&keys.encryption_key, &self.master_iv)
            .map_err(|e| Error::Encryption(format!("Failed to init AES for session key: {:?}", e)))?
            .decrypt_padded_mut::<Pkcs7>(&mut enc_data_iv_session_clone)
            .map_err(|e| Error::Encryption(format!("Failed to decrypt session key: {:?}", e)))?;

        // Extract data IV (first 16 bytes) and session key (next 32 bytes, total 48 for AES-256)
        // The doc says: "encrypted data IV + session key (64 bytes)"
        // "Generate a random 256-bit session key" -> 32 bytes
        // "Generate a random data IV" -> AES block size, 16 bytes for AES-256
        // So, 16 (IV) + 32 (session key) = 48 bytes of plaintext. PKCS7 padding makes it 64.
        if data_iv_session_key_plaintext.len() < 48 {
             return Err(Error::Encryption("Decrypted session key data too short".into()));
        }
        let data_iv = &data_iv_session_key_plaintext[0..16];
        let session_key = &data_iv_session_key_plaintext[16..48];

        // 3. Decrypt ciphertext using session key and data IV
        let mut ciphertext_clone = self.ciphertext.clone();
        let plaintext = Aes256CbcDec::new_from_slices(session_key, data_iv)
            .map_err(|e| Error::Encryption(format!("Failed to init AES for data: {:?}", e)))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_clone)
            .map_err(|e| Error::Encryption(format!("Failed to decrypt data: {:?}", e)))?;

        Ok(plaintext.to_vec())
    }
}


// Binary Node structure
// Stored LZ4-compressed and (optionally) encrypted in "treepacks"
// This struct is for the actual binary data.
pub struct NodeBin {
    pub is_tree: bool,
    pub tree_blob_loc: Option<BlobLoc>, // present if is_tree is true
    pub computer_os_type: u32,
    // pub data_blob_locs: Vec<BlobLoc>, // Needs custom parsing due to count prefix
    pub acl_blob_loc: Option<BlobLoc>, // present if acl_blob_loc_is_not_nil is true
    // pub xattrs_blob_locs: Vec<BlobLoc>, // Needs custom parsing due to count prefix
    pub item_size: u64,
    pub contained_files_count: u64,
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
    pub mac_st_flags: i32,
    pub win_attrs: u32,
    pub win_reparse_tag: Option<u32>, // if Tree version >= 2
    pub win_reparse_point_is_directory: Option<bool>, // if Tree version >= 2
}

// Plaintext structure for encryptedkeyset.dat
#[derive(Debug)]
pub struct EncryptedKeySetPlaintext {
    pub encryption_version: u32,
    pub encryption_key: Vec<u8>, // 64 bytes
    pub hmac_key: Vec<u8>,       // 64 bytes
    pub blob_identifier_salt: Vec<u8>, // 64 bytes
}

// Structure for the encrypted encryptedkeyset.dat file
// We'll need a method to decrypt this into EncryptedKeySetPlaintext
#[derive(Debug)]
pub struct EncryptedKeySet {
    // Actual file header: ARQ_ENCRYPTED_MASTER_KEYS (25 bytes)
    // Followed by: salt (8 bytes), hmac_sha256 (32 bytes), iv (16 bytes), ciphertext (...)
    raw_data: Vec<u8>, // Store the full file content for parsing
}

impl EncryptedKeySet {
    const HEADER_PREFIX: &'static [u8] = b"ARQ_ENCRYPTED_MASTER_KEYS"; // 25 bytes
    const SALT_OFFSET: usize = 25;
    const SALT_LEN: usize = 8;
    const HMAC_OFFSET: usize = Self::SALT_OFFSET + Self::SALT_LEN; // 33
    const HMAC_LEN: usize = 32;
    const IV_OFFSET: usize = Self::HMAC_OFFSET + Self::HMAC_LEN; // 65
    const IV_LEN: usize = 16;
    const CIPHERTEXT_OFFSET: usize = Self::IV_OFFSET + Self::IV_LEN; // 81

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        if buffer.len() < Self::CIPHERTEXT_OFFSET {
            return Err(Error::InvalidData("EncryptedKeySet file too short".into()));
        }
        if !buffer.starts_with(Self::HEADER_PREFIX) {
            return Err(Error::InvalidData("Invalid EncryptedKeySet header".into()));
        }
        Ok(EncryptedKeySet { raw_data: buffer })
    }

    fn salt(&self) -> &[u8] {
        &self.raw_data[Self::SALT_OFFSET..Self::SALT_OFFSET + Self::SALT_LEN]
    }

    fn hmac_sha256_stored(&self) -> &[u8] {
        &self.raw_data[Self::HMAC_OFFSET..Self::HMAC_OFFSET + Self::HMAC_LEN]
    }

    fn iv(&self) -> &[u8] {
        &self.raw_data[Self::IV_OFFSET..Self::IV_OFFSET + Self::IV_LEN]
    }

    fn ciphertext(&self) -> &[u8] {
        &self.raw_data[Self::CIPHERTEXT_OFFSET..]
    }

    pub fn decrypt(&self, password: &str) -> Result<EncryptedKeySetPlaintext> {
        // 1. Derive a 64-byte key from the encryption password using PBKDF2-SHA256, the salt, and 200,000 rounds.
        let mut derived_key = [0u8; 64]; // 2 * 32 for AES key and HMAC key
        pbkdf2::derive(
            digest::SHA256, // Arq7 uses SHA256 for PBKDF2 with encryptedkeyset.dat
            std::num::NonZeroU32::new(200_000).unwrap(),
            self.salt(),
            password.as_bytes(),
            &mut derived_key,
        );

        let aes_key = &derived_key[0..32];
        let hmac_key_for_verification = &derived_key[32..64];

        // 2. Calculate the HMACSHA256 of IV + ciphertext and verify it matches the value in the file.
        // The documentation says "HMACSHA256 of IV + ciphertext" using the *derived key*.
        // It's common to use a portion of the derived key for this HMAC.
        // The existing code (object_encryption.rs) for encryptionv3.dat uses the *second 32 bytes* of the derived key.
        // Let's assume the same pattern here.

        let mut data_to_hmac = Vec::new();
        data_to_hmac.extend_from_slice(self.iv());
        data_to_hmac.extend_from_slice(self.ciphertext());

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(hmac_key_for_verification)
            .map_err(|_| Error::Encryption("Failed to initialize HMAC for verification".into()))?;
        mac.update(&data_to_hmac);
        let calculated_hmac = mac.finalize().into_bytes();

        if calculated_hmac[..] != self.hmac_sha256_stored()[..] {
            return Err(Error::WrongPassword); // Or a more specific HMAC mismatch error
        }

        // 3. Decrypt the ciphertext using the derived key (first 32 bytes for AES) and the IV from the file.
        let mut ciphertext_mut = self.ciphertext().to_vec();
        let plaintext = Aes256CbcDec::new_from_slices(aes_key, self.iv())
            .map_err(|e| Error::Encryption(format!("Failed to initialize AES decryptor: {:?}", e)))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_mut)
            .map_err(|e| Error::Encryption(format!("Failed to decrypt keyset: {:?}", e)))?;

        // Now parse the plaintext
        // Plaintext format:
        // encryption version                  00 00 00 03 (4 bytes)
        // encryption key length               00 00 00 00 00 00 00 40 (8 bytes, value 64)
        // encryption key                      xx xx xx xx 64 bytes
        // HMAC key length                     00 00 00 00 00 00 00 40 (8 bytes, value 64)
        // HMAC key                            xx xx xx xx 64 bytes
        // blob identifier salt length         00 00 00 00 00 00 00 40 (8 bytes, value 64)
        // blob identifier salt                xx xx xx xx 64 bytes

        let mut reader = BufReader::new(std::io::Cursor::new(plaintext));

        let encryption_version = reader.read_u32_be()?;
        if encryption_version != 3 {
            // Arq documentation specifies version 3 for this plaintext format.
            // Potentially handle other versions if they exist or error out.
            return Err(Error::InvalidData(format!("Unexpected encryption keyset plaintext version: {}", encryption_version)));
        }

        let enc_key_len = reader.read_u64_be()?;
        if enc_key_len != 64 {
            return Err(Error::InvalidData(format!("Unexpected encryption key length: {}", enc_key_len)));
        }
        let mut encryption_key = vec![0u8; enc_key_len as usize];
        reader.read_exact(&mut encryption_key)?;

        let hmac_key_len = reader.read_u64_be()?;
        if hmac_key_len != 64 {
            return Err(Error::InvalidData(format!("Unexpected HMAC key length: {}", hmac_key_len)));
        }
        let mut hmac_key = vec![0u8; hmac_key_len as usize];
        reader.read_exact(&mut hmac_key)?;

        let blob_id_salt_len = reader.read_u64_be()?;
        if blob_id_salt_len != 64 {
             return Err(Error::InvalidData(format!("Unexpected blob identifier salt length: {}", blob_id_salt_len)));
        }
        let mut blob_identifier_salt = vec![0u8; blob_id_salt_len as usize];
        reader.read_exact(&mut blob_identifier_salt)?;

        Ok(EncryptedKeySetPlaintext {
            encryption_version,
            encryption_key,
            hmac_key,
            blob_identifier_salt,
        })
    }
}


// Placeholder for Arq 7 specific object encryption details if different from existing
// The documentation for "Encrypted Object" seems very similar to the existing EncryptedObject.
// If it's identical, we might not need a new struct, just ensure the key derivation for
// encryptedkeyset.dat is correct.

// The documentation mentions "Node" and "Tree" are stored as LZ4-compressed and
// (optionally) encrypted binary data.
// The `NodeJson` above is for the JSON representation within a `BackupRecord`.
// We will need separate structs/parsers for the binary `Node` and `Tree` formats.
// I've added placeholders `NodeBin` and `Tree` for these.

// Placeholder for the main Arq7 backup context
pub struct Arq7Backup {
    pub base_path: String,
    pub config: BackupConfig,
    pub folders_meta: BackupFolders,
    pub keys: Option<EncryptedKeySetPlaintext>, // None if not encrypted
                                               // Potentially cache of backup folder details, etc.
}

// TODO:
// - Implement `new` or `from_reader` for these structs, especially for binary ones.
// - Implement decryption for `EncryptedKeySet`.
// - Implement parsing for binary `Node` and `Tree`.
// - Decide if BackupRecord's content is Plist or JSON. Documentation example is JSON-like.
//   The current `arq` library uses `plist` crate. If Arq7 uses JSON for backup records,
//   we'll use `serde_json`. If it's Plist containing this structure, adapt accordingly.
//   The example shows `{ key = value; ... }` which is more Plist-like than pure JSON.
//   For now, `Deserialize` assumes JSON. This will need verification.
//   If it's a non-standard plist format, custom parsing might be needed.
//   The current `folder.rs` uses `plist::from_reader`.
//   Let's assume for now that the backup record is a plist file, and its content can be deserialized
//   into the BackupRecord struct if the plist content matches this structure.
//   The `arq5_bucket_xml` field being a string containing XML plist suggests other parts might be plist too.
//   If the outer container is plist and inner is JSON, that's also possible.
//   Given the existing library uses plist heavily, it's safer to assume plist for .backuprecord files.
//   The `serde` derive might not work directly with `plist` if the structure differs too much.
//   The example format `key = value;` is Objective-C property list text format.
//   The `plist` crate in Rust typically handles XML and binary plists.
//   If Arq7 uses the text plist format, we might need a different parser or convert it to XML first.
//   For now, I'll keep the serde derive for JSON and address plist parsing in the implementation step.
//   It's possible the documentation simplifies the representation.

impl BackupRecord {
    pub fn from_path_and_keys<P: AsRef<Path>>(
        path: P,
        // True if the overall backup config says it's encrypted.
        // Individual objects like BackupRecord still start with ARQO if encrypted.
        is_globally_encrypted: bool,
        keys: Option<&EncryptedKeySetPlaintext>, // Provide if is_globally_encrypted is true
    ) -> Result<Self> {
        let mut file_bytes = Vec::new();
        File::open(path)?.read_to_end(&mut file_bytes)?;

        let processed_bytes = if is_globally_encrypted {
            if keys.is_none() {
                return Err(Error::Encryption("Keys required for encrypted backup record".into()));
            }
            if file_bytes.starts_with(Arq7EncryptedObject::HEADER) {
                let encrypted_object = Arq7EncryptedObject::from_bytes(&file_bytes)?;
                encrypted_object.decrypt(keys.unwrap())?
            } else {
                // If globally encrypted but this specific file doesn't have ARQO header,
                // it might be an error or an unencrypted file within an encrypted backup set (unlikely for critical metadata).
                // For now, assume critical files like backuprecord are encrypted if the backup set is.
                return Err(Error::InvalidData("Expected ARQO header for encrypted backup record".into()));
            }
        } else {
            // Not globally encrypted, use bytes as is (assuming they are not ARQO wrapped)
            if file_bytes.starts_with(Arq7EncryptedObject::HEADER) {
                 return Err(Error::InvalidData("Unexpected ARQO header for unencrypted backup record".into()));
            }
            file_bytes
        };

        // Decompress LZ4 data (4-byte big-endian length followed by LZ4 block format)
        // The `lz4_decompress_with_prefix` should handle this.
        let decompressed_bytes = lz4_decompress_with_prefix(&processed_bytes)?;

        // Parse the decompressed bytes as a plist.
        // The `plist` crate's `from_bytes` can parse XML and binary plists.
        // If Arq7 uses text plists, this might fail or need adjustment.
        // The example `key = value;` is text plist.
        // `plist::Value::from_reader` might be more flexible if we can detect format.
        // For now, trying `from_bytes`. If it fails, we'll need to investigate plist text parsing.
        let backup_record: BackupRecord = plist::from_bytes(&decompressed_bytes)
            .map_err(|e| Error::PlistDecode(format!("Failed to parse BackupRecord plist: {}", e)))?;

        Ok(backup_record)
    }
}


use std::path::PathBuf;
use std::fs;

// Add this new module to lib.rs
// pub mod arq7_format;

#[derive(Debug)]
pub struct Arq7BackupSet {
    pub base_path: PathBuf,
    pub config: BackupConfig,
    pub keys: Option<EncryptedKeySetPlaintext>, // None if not encrypted
    pub backup_folders_index: BackupFolders, // From backupfolders.json
    // loaded_backup_folders: BTreeMap<String, BackupFolder>, // Optional cache
}

impl Arq7BackupSet {
    pub fn load<P: AsRef<Path>>(base_path: P, password: Option<&str>) -> Result<Self> {
        let base_path_buf = base_path.as_ref().to_path_buf();

        // 1. Read backupconfig.json
        let config_path = base_path_buf.join("backupconfig.json");
        let config = BackupConfig::from_path(config_path)?;

        // 2. Read encryptedkeyset.dat if encrypted
        let mut keys: Option<EncryptedKeySetPlaintext> = None;
        if config.is_encrypted {
            let p = password.ok_or_else(|| Error::Input(
                "Password required for encrypted backup set".to_string()
            ))?;
            let keyset_path = base_path_buf.join("encryptedkeyset.dat");
            let encrypted_keyset = EncryptedKeySet::from_path(keyset_path)?;
            keys = Some(encrypted_keyset.decrypt(p)?);
        }

        // 3. Read backupfolders.json
        let folders_index_path = base_path_buf.join("backupfolders.json");
        let backup_folders_index = BackupFolders::from_path(folders_index_path)?;

        Ok(Arq7BackupSet {
            base_path: base_path_buf,
            config,
            keys,
            backup_folders_index,
            // loaded_backup_folders: BTreeMap::new(),
        })
    }

    /// Lists the actual backup folder configurations by scanning the `backupfolders` directory.
    pub fn list_backup_folder_configs(&self) -> Result<Vec<BackupFolder>> {
        let bf_dir_path = self.base_path.join("backupfolders");
        let mut configs = Vec::new();

        if !bf_dir_path.is_dir() {
            // If there's no backupfolders directory, there are no backup folders configured yet,
            // or it's a very minimal/corrupt backup set.
            return Ok(configs);
        }

        for entry in fs::read_dir(bf_dir_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // Expect directory name to be a UUID
                // let folder_uuid = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                let config_file_path = path.join("backupfolder.json");
                if config_file_path.exists() {
                    match BackupFolder::from_path(config_file_path) {
                        Ok(bf_config) => configs.push(bf_config),
                        Err(e) => {
                            // Log or collect errors for partial success?
                            // For now, let one bad folder config fail the whole listing for simplicity.
                            return Err(Error::Io(format!("Failed to read backupfolder.json for {:?}: {}", path, e)));
                        }
                    }
                }
            }
        }
        Ok(configs)
    }

    /// Lists backup records for a specific folder UUID.
    pub fn list_backup_records(&self, folder_uuid: &str) -> Result<Vec<BackupRecord>> {
        let records_base_path = self.base_path.join("backupfolders").join(folder_uuid).join("backuprecords");
        let mut records = Vec::new();

        if !records_base_path.is_dir() {
            return Ok(records); // No records for this folder UUID
        }

        // Backup records are in subdirectories like "00161", then files like "4294169.backuprecord"
        // Need to walk the directory recursively or handle known depth.
        // For now, assuming one level of subdirectories for organization (e.g., year or similar).
        // The example shows "00161/4294169.backuprecord".
        // Let's do a simple recursive scan for .backuprecord files.

        let mut files_to_parse = Vec::new();
        self.find_backup_record_files(&records_base_path, &mut files_to_parse)?;

        for record_file_path in files_to_parse {
            match BackupRecord::from_path_and_keys(
                &record_file_path,
                self.config.is_encrypted,
                self.keys.as_ref()
            ) {
                Ok(record) => records.push(record),
                Err(e) => {
                    // Log or collect errors?
                    eprintln!("Failed to parse backup record {:?}: {}", record_file_path, e);
                    // Optionally skip problematic records: continue;
                    // For now, let one bad record fail the listing.
                    return Err(e);
                }
            }
        }

        // Sort records by creation date, newest first
        records.sort_by(|a, b| b.creation_date.cmp(&a.creation_date));

        Ok(records)
    }

    // Helper to recursively find .backuprecord files
    fn find_backup_record_files(&self, dir: &Path, files_list: &mut Vec<PathBuf>) -> Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    self.find_backup_record_files(&path, files_list)?;
                } else if path.extension().map_or(false, |ext| ext == "backuprecord") {
                    files_list.push(path);
                }
            }
        }
        Ok(())
    }

    // TODO: Implement functions to read actual file/directory content from a backup record
    // This will involve parsing binary Node/Tree data from packs or standalone blobs.
}
