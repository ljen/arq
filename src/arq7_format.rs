// serde::Deserialize is used by derive macros, so it's needed even if not directly referenced.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, BufReader, Cursor, Seek, SeekFrom};
use std::fs::File;
use std::path::Path;

use crate::error::{Result, Error};
use crate::type_utils::ArqRead;

// For EncryptedKeySet decryption
use ring::pbkdf2; // No longer aliasing ring::digest
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes::cipher::block_padding::Pkcs7;
use digest::KeyInit; // For Hmac::new_from_slice
use hmac::Mac; // For mac.update() and mac.finalize()

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
    pub is_worm: bool,
    pub contains_glacier_archives: bool,
    pub additional_unpacked_blob_dirs: Vec<String>,
    pub chunker_version: u32,
    pub computer_name: String,
    pub computer_serial: String,
    pub blob_storage_class: String,
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
    pub storage_class: String,
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
    pub compression_type: u32,
}

// Struct for Node in a backup record or a Tree
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NodeJson {
    #[serde(rename = "changeTime_nsec")]
    pub change_time_nsec: i64,
    #[serde(rename = "changeTime_sec")]
    pub change_time_sec: i64,
    #[serde(default)]
    pub computer_os_type: Option<u32>,
    #[serde(default)]
    pub contained_files_count: Option<u64>,
    #[serde(rename = "creationTime_nsec")]
    pub creation_time_nsec: i64,
    #[serde(rename = "creationTime_sec")]
    pub creation_time_sec: i64,
    #[serde(default)]
    pub data_blob_locs: Vec<BlobLoc>,
    #[serde(default)]
    pub deleted: Option<bool>,
    pub is_tree: bool,
    pub item_size: u64,
    #[serde(default, rename = "mac_st_dev")]
    pub mac_st_dev: Option<i32>,
    #[serde(default, rename = "mac_st_flags")]
    pub mac_st_flags: Option<i32>,
    #[serde(default, rename = "mac_st_gid")]
    pub mac_st_gid: Option<u32>,
    #[serde(default, rename = "mac_st_ino")]
    pub mac_st_ino: Option<u64>,
    #[serde(default, rename = "mac_st_mode")]
    pub mac_st_mode: Option<u32>,
    #[serde(default, rename = "mac_st_nlink")]
    pub mac_st_nlink: Option<u32>,
    #[serde(default, rename = "mac_st_rdev")]
    pub mac_st_rdev: Option<i32>,
    #[serde(default, rename = "mac_st_uid")]
    pub mac_st_uid: Option<u32>,
    #[serde(rename = "modificationTime_nsec")]
    pub modification_time_nsec: i64,
    #[serde(rename = "modificationTime_sec")]
    pub modification_time_sec: i64,
    #[serde(default)]
    pub tree_blob_loc: Option<BlobLoc>,
    #[serde(default, rename = "winAttrs")]
    pub win_attrs: Option<u32>,
    #[serde(default)]
    pub xattrs_blob_locs: Vec<BlobLoc>,
}

impl BackupConfig {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader)
            .map_err(|e| Error::JsonDecode(format!("Failed to parse BackupConfig: {}", e)))
    }
}

impl BackupFolders {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader)
            .map_err(|e| Error::JsonDecode(format!("Failed to parse BackupFolders: {}", e)))
    }
}

impl BackupFolder {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader)
            .map_err(|e| Error::JsonDecode(format!("Failed to parse BackupFolder: {}", e)))
    }
}

#[derive(Debug, Clone)]
pub struct TreeBin {
    pub version: u32,
    pub child_nodes_by_name: BTreeMap<String, NodeBin>,
}

impl TreeBin {
    pub fn from_reader<R: Read + ArqRead>(reader: &mut R) -> Result<Self> {
        let version = reader.read_arq_u32()?;
        let child_nodes_by_name_count = reader.read_arq_u64()?;
        let mut child_nodes_by_name = BTreeMap::new();
        for _ in 0..child_nodes_by_name_count {
            let child_name = reader.read_arq_string()?;
            let child_node = NodeBin::from_reader(reader, version)?;
            child_nodes_by_name.insert(child_name, child_node);
        }
        Ok(TreeBin { version, child_nodes_by_name })
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Arq5TreeBlobKey {
    pub archive_size: u64,
    pub compression_type: u32,
    pub sha1: String,
    pub storage_type: u32,
    pub stretch_encryption_key: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupPlanJson {
    pub active: u8,
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
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupRecord {
    pub archived: u8,
    pub arq_version: String,
    pub backup_folder_uuid: String,
    pub backup_plan_json: BackupPlanJson,
    pub backup_plan_uuid: String,
    #[serde(default)]
    pub computer_os_type: Option<u32>,
    #[serde(default)]
    pub copied_from_commit: bool,
    #[serde(default)]
    pub copied_from_snapshot: bool,
    pub creation_date: i64,
    #[serde(default)]
    pub disk_identifier: Option<String>,
    #[serde(default)]
    pub error_count: u64,
    #[serde(rename = "isComplete")]
    pub is_complete: bool,
    #[serde(default)]
    pub local_mount_point: Option<String>,
    pub local_path: String,
    pub node: Option<NodeJson>,
    pub relative_path: String,
    pub storage_class: String,
    pub version: u32,
    #[serde(default)]
    pub volume_name: Option<String>,
    #[serde(rename = "arq5BucketXML")]
    pub arq5_bucket_xml: Option<String>,
    #[serde(rename = "arq5TreeBlobKey")]
    pub arq5_tree_blob_key: Option<Arq5TreeBlobKey>,
}

use crate::plist;

pub struct Tree {
    pub version: u32,
}

#[derive(Debug)]
pub struct Arq7EncryptedObject {
    hmac_sha256: Vec<u8>,
    master_iv: Vec<u8>,
    encrypted_data_iv_session_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Arq7EncryptedObject {
    pub const HEADER: &'static [u8] = b"ARQO";
    const HMAC_LEN: usize = 32;
    const MASTER_IV_LEN: usize = 16;
    const ENC_DATA_IV_SESSION_KEY_LEN: usize = 64;

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
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
        Ok(Arq7EncryptedObject { hmac_sha256, master_iv, encrypted_data_iv_session_key, ciphertext })
    }

    pub fn decrypt(&self, keys: &EncryptedKeySetPlaintext) -> Result<Vec<u8>> {
        let mut data_to_hmac = Vec::new();
        data_to_hmac.extend_from_slice(&self.master_iv);
        data_to_hmac.extend_from_slice(&self.encrypted_data_iv_session_key);
        data_to_hmac.extend_from_slice(&self.ciphertext);

        let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&keys.hmac_key)
            .map_err(|_| Error::Encryption("Failed to initialize HMAC for Arq7EncryptedObject".into()))?;
        mac.update(&data_to_hmac);
        let calculated_hmac = mac.finalize().into_bytes();

        if calculated_hmac[..] != self.hmac_sha256[..] {
            return Err(Error::Encryption("Arq7EncryptedObject HMAC mismatch".into()));
        }

        let mut enc_data_iv_session_clone = self.encrypted_data_iv_session_key.clone();
        let data_iv_session_key_plaintext = Aes256CbcDec::new_from_slices(&keys.encryption_key, &self.master_iv)
            .map_err(|e| Error::Encryption(format!("Failed to init AES for session key: {:?}", e)))?
            .decrypt_padded_mut::<Pkcs7>(&mut enc_data_iv_session_clone)
            .map_err(|e| Error::Encryption(format!("Failed to decrypt session key: {:?}", e)))?;

        if data_iv_session_key_plaintext.len() < 48 {
             return Err(Error::Encryption("Decrypted session key data too short".into()));
        }
        let data_iv = &data_iv_session_key_plaintext[0..16];
        let session_key = &data_iv_session_key_plaintext[16..48];

        let mut ciphertext_clone = self.ciphertext.clone();
        Aes256CbcDec::new_from_slices(session_key, data_iv)
            .map_err(|e| Error::Encryption(format!("Failed to init AES for data: {:?}", e)))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_clone)
            .map_err(|e| Error::Encryption(format!("Failed to decrypt data: {:?}", e)))
            .map(|pt| pt.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct NodeBin {
    pub is_tree: bool,
    pub tree_blob_loc: Option<BlobLoc>,
    pub computer_os_type: u32,
    pub data_blob_locs: Vec<BlobLoc>,
    pub acl_blob_loc: Option<BlobLoc>,
    pub xattrs_blob_locs: Vec<BlobLoc>,
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
    pub win_reparse_tag: Option<u32>,
    pub win_reparse_point_is_directory: Option<bool>,
}

impl BlobLoc {
    pub fn from_reader<R: Read + ArqRead>(reader: &mut R) -> Result<Self> {
        let blob_identifier = reader.read_arq_string()?;
        if blob_identifier.is_empty() {}
        let is_packed = reader.read_arq_bool()?;
        let relative_path = reader.read_arq_string()?;
        let offset = reader.read_arq_u64()?;
        let length = reader.read_arq_u64()?;
        let stretch_encryption_key = reader.read_arq_bool()?;
        let compression_type = reader.read_arq_u32()?;
        Ok(BlobLoc { blob_identifier, is_packed, relative_path, offset, length, stretch_encryption_key, compression_type })
    }
}

impl NodeBin {
    pub fn from_reader<R: Read + ArqRead>(reader: &mut R, tree_version: u32) -> Result<Self> {
        let is_tree = reader.read_arq_bool()?;
        let tree_blob_loc = if is_tree { Some(BlobLoc::from_reader(reader)?) } else { None };
        let computer_os_type = reader.read_arq_u32()?;
        let data_blob_locs_count = reader.read_arq_u64()?;
        let mut data_blob_locs = Vec::with_capacity(data_blob_locs_count as usize);
        for _ in 0..data_blob_locs_count { data_blob_locs.push(BlobLoc::from_reader(reader)?); }
        let acl_blob_loc_is_not_nil = reader.read_arq_bool()?;
        let acl_blob_loc = if acl_blob_loc_is_not_nil { Some(BlobLoc::from_reader(reader)?) } else { None };
        let xattrs_blob_loc_count = reader.read_arq_u64()?;
        let mut xattrs_blob_locs = Vec::with_capacity(xattrs_blob_loc_count as usize);
        for _ in 0..xattrs_blob_loc_count { xattrs_blob_locs.push(BlobLoc::from_reader(reader)?); }
        let item_size = reader.read_arq_u64()?;
        let contained_files_count = reader.read_arq_u64()?;
        let mtime_sec = reader.read_arq_i64()?;
        let mtime_nsec = reader.read_arq_i64()?;
        let ctime_sec = reader.read_arq_i64()?;
        let ctime_nsec = reader.read_arq_i64()?;
        let create_time_sec = reader.read_arq_i64()?;
        let create_time_nsec = reader.read_arq_i64()?;
        let username = reader.read_arq_string()?;
        let group_name = reader.read_arq_string()?;
        let deleted = reader.read_arq_bool()?;
        let mac_st_dev = reader.read_arq_i32()?;
        let mac_st_ino = reader.read_arq_u64()?;
        let mac_st_mode = reader.read_arq_u32()?;
        let mac_st_nlink = reader.read_arq_u32()?;
        let mac_st_uid = reader.read_arq_u32()?;
        let mac_st_gid = reader.read_arq_u32()?;
        let mac_st_rdev = reader.read_arq_i32()?;
        let mac_st_flags = reader.read_arq_i32()?;
        let win_attrs = reader.read_arq_u32()?;
        let mut win_reparse_tag = None;
        let mut win_reparse_point_is_directory = None;
        if tree_version >= 2 {
            win_reparse_tag = Some(reader.read_arq_u32()?);
            win_reparse_point_is_directory = Some(reader.read_arq_bool()?);
        }
        Ok(NodeBin { is_tree, tree_blob_loc, computer_os_type, data_blob_locs, acl_blob_loc, xattrs_blob_locs, item_size, contained_files_count, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec, create_time_sec, create_time_nsec, username, group_name, deleted, mac_st_dev, mac_st_ino, mac_st_mode, mac_st_nlink, mac_st_uid, mac_st_gid, mac_st_rdev, mac_st_flags, win_attrs, win_reparse_tag, win_reparse_point_is_directory })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedKeySetPlaintext {
    pub encryption_version: u32,
    pub encryption_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub blob_identifier_salt: Vec<u8>,
}

#[derive(Debug)]
pub struct EncryptedKeySet {
    raw_data: Vec<u8>,
}

impl EncryptedKeySet {
    const HEADER_PREFIX: &'static [u8] = b"ARQ_ENCRYPTED_MASTER_KEYS";
    const SALT_OFFSET: usize = 25;
    const SALT_LEN: usize = 8;
    const HMAC_OFFSET: usize = Self::SALT_OFFSET + Self::SALT_LEN;
    const HMAC_LEN: usize = 32;
    const IV_OFFSET: usize = Self::HMAC_OFFSET + Self::HMAC_LEN;
    const IV_LEN: usize = 16;
    const CIPHERTEXT_OFFSET: usize = Self::IV_OFFSET + Self::IV_LEN;

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        if buffer.len() < Self::CIPHERTEXT_OFFSET { return Err(Error::InvalidData("EncryptedKeySet file too short".into())); }
        if !buffer.starts_with(Self::HEADER_PREFIX) { return Err(Error::InvalidData("Invalid EncryptedKeySet header".into())); }
        Ok(EncryptedKeySet { raw_data: buffer })
    }

    fn salt(&self) -> &[u8] { &self.raw_data[Self::SALT_OFFSET..Self::SALT_OFFSET + Self::SALT_LEN] }
    fn hmac_sha256_stored(&self) -> &[u8] { &self.raw_data[Self::HMAC_OFFSET..Self::HMAC_OFFSET + Self::HMAC_LEN] }
    fn iv(&self) -> &[u8] { &self.raw_data[Self::IV_OFFSET..Self::IV_OFFSET + Self::IV_LEN] }
    fn ciphertext(&self) -> &[u8] { &self.raw_data[Self::CIPHERTEXT_OFFSET..] }

    pub fn decrypt(&self, password: &str) -> Result<EncryptedKeySetPlaintext> {
        let mut derived_key = [0u8; 64];
        pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256, // Corrected
            std::num::NonZeroU32::new(200_000).unwrap(),
            self.salt(),
            password.as_bytes(),
            &mut derived_key,
        );

        let aes_key = &derived_key[0..32];
        let hmac_key_for_verification = &derived_key[32..64];

        let mut data_to_hmac = Vec::new();
        data_to_hmac.extend_from_slice(self.iv());
        data_to_hmac.extend_from_slice(self.ciphertext());

        let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(hmac_key_for_verification) // Corrected
            .map_err(|_| Error::Encryption("Failed to initialize HMAC for verification".into()))?;
        mac.update(&data_to_hmac);
        let calculated_hmac = mac.finalize().into_bytes();

        if calculated_hmac[..] != self.hmac_sha256_stored()[..] { return Err(Error::WrongPassword); }

        let mut ciphertext_mut = self.ciphertext().to_vec();
        let plaintext_bytes = Aes256CbcDec::new_from_slices(aes_key, self.iv())
            .map_err(|e| Error::Encryption(format!("Failed to initialize AES decryptor: {:?}", e)))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_mut)
            .map_err(|e| Error::Encryption(format!("Failed to decrypt keyset: {:?}", e)))?;

        let mut reader = Cursor::new(plaintext_bytes.as_ref()); // Corrected: use Cursor with ArqRead

        let encryption_version = reader.read_arq_u32()?;
        if encryption_version != 3 {
            return Err(Error::InvalidData(format!("Unexpected encryption keyset plaintext version: {}", encryption_version)));
        }

        let enc_key_len = reader.read_arq_u64()?;
        if enc_key_len != 64 {
            return Err(Error::InvalidData(format!("Unexpected encryption key length: {}", enc_key_len)));
        }
        let mut encryption_key = vec![0u8; enc_key_len as usize];
        reader.read_exact(&mut encryption_key)?;

        let hmac_key_len = reader.read_arq_u64()?;
        if hmac_key_len != 64 {
            return Err(Error::InvalidData(format!("Unexpected HMAC key length: {}", hmac_key_len)));
        }
        let mut hmac_key = vec![0u8; hmac_key_len as usize];
        reader.read_exact(&mut hmac_key)?;

        let blob_id_salt_len = reader.read_arq_u64()?;
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

pub struct Arq7Backup {
    pub base_path: String,
    pub config: BackupConfig,
    pub folders_meta: BackupFolders,
    pub keys: Option<EncryptedKeySetPlaintext>,
}

impl BackupRecord {
    pub fn from_path_and_keys<P: AsRef<Path>>(
        path: P,
        is_globally_encrypted: bool,
        keys: Option<&EncryptedKeySetPlaintext>,
    ) -> Result<Self> {
        let mut file_bytes = Vec::new();
        File::open(path)?.read_to_end(&mut file_bytes)?;

        let processed_bytes = if is_globally_encrypted {
            if keys.is_none() { return Err(Error::Encryption("Keys required for encrypted backup record".into())); }
            if file_bytes.starts_with(Arq7EncryptedObject::HEADER) {
                let encrypted_object = Arq7EncryptedObject::from_bytes(&file_bytes)?;
                encrypted_object.decrypt(keys.unwrap())?
            } else {
                return Err(Error::InvalidData("Expected ARQO header for encrypted backup record".into()));
            }
        } else {
            if file_bytes.starts_with(Arq7EncryptedObject::HEADER) {
                 return Err(Error::InvalidData("Unexpected ARQO header for unencrypted backup record".into()));
            }
            file_bytes
        };

        let decompressed_bytes = crate::lz4::decompress(&processed_bytes)?; // Corrected
        let backup_record: BackupRecord = plist::from_bytes(&decompressed_bytes)
            .map_err(|e| Error::PlistDecode(format!("Failed to parse BackupRecord plist: {}", e)))?;
        Ok(backup_record)
    }
}

use std::path::PathBuf;
use std::fs;

#[derive(Debug)]
pub struct Arq7BackupSet {
    pub base_path: PathBuf,
    pub config: BackupConfig,
    pub keys: Option<EncryptedKeySetPlaintext>,
    pub backup_folders_index: BackupFolders,
}

impl Arq7BackupSet {
    pub fn load<P: AsRef<Path>>(base_path: P, password: Option<&str>) -> Result<Self> {
        let base_path_buf = base_path.as_ref().to_path_buf();
        let config_path = base_path_buf.join("backupconfig.json");
        let config = BackupConfig::from_path(config_path)?;
        let mut keys: Option<EncryptedKeySetPlaintext> = None;
        if config.is_encrypted {
            let p = password.ok_or_else(|| Error::Input( "Password required for encrypted backup set".to_string() ))?;
            let keyset_path = base_path_buf.join("encryptedkeyset.dat");
            let encrypted_keyset = EncryptedKeySet::from_path(keyset_path)?;
            keys = Some(encrypted_keyset.decrypt(p)?);
        }
        let folders_index_path = base_path_buf.join("backupfolders.json");
        let backup_folders_index = BackupFolders::from_path(folders_index_path)?;
        Ok(Arq7BackupSet { base_path: base_path_buf, config, keys, backup_folders_index })
    }

    pub fn list_backup_folder_configs(&self) -> Result<Vec<BackupFolder>> {
        let bf_dir_path = self.base_path.join("backupfolders");
        let mut configs = Vec::new();
        if !bf_dir_path.is_dir() { return Ok(configs); }
        for entry in fs::read_dir(bf_dir_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let config_file_path = path.join("backupfolder.json");
                if config_file_path.exists() {
                    match BackupFolder::from_path(config_file_path) {
                        Ok(bf_config) => configs.push(bf_config),
                        Err(e) => { return Err(Error::Io(format!("Failed to read backupfolder.json for {:?}: {}", path, e))); }
                    }
                }
            }
        }
        Ok(configs)
    }

    pub fn list_backup_records(&self, folder_uuid: &str) -> Result<Vec<BackupRecord>> {
        let records_base_path = self.base_path.join("backupfolders").join(folder_uuid).join("backuprecords");
        let mut records = Vec::new();
        if !records_base_path.is_dir() { return Ok(records); }
        let mut files_to_parse = Vec::new();
        self.find_backup_record_files(&records_base_path, &mut files_to_parse)?;
        for record_file_path in files_to_parse {
            match BackupRecord::from_path_and_keys( &record_file_path, self.config.is_encrypted, self.keys.as_ref() ) {
                Ok(record) => records.push(record),
                Err(e) => { eprintln!("Failed to parse backup record {:?}: {}", record_file_path, e); return Err(e); }
            }
        }
        records.sort_by(|a, b| b.creation_date.cmp(&a.creation_date));
        Ok(records)
    }

    fn find_backup_record_files(&self, dir: &Path, files_list: &mut Vec<PathBuf>) -> Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() { self.find_backup_record_files(&path, files_list)?; }
                else if path.extension().map_or(false, |ext| ext == "backuprecord") { files_list.push(path); }
            }
        }
        Ok(())
    }

    pub fn fetch_blob_data_and_decompress(&self, blob_loc: &BlobLoc) -> Result<Vec<u8>> {
        let raw_object_bytes = if blob_loc.is_packed {
            let pack_file_path = self.base_path.join(blob_loc.relative_path.trim_start_matches('/'));
            let mut index_file_path = pack_file_path.clone();
            index_file_path.set_extension("index");
            if !pack_file_path.exists() { return Err(Error::Io(format!("Pack file not found: {:?}", pack_file_path))); }
            if !index_file_path.exists() { return Err(Error::Io(format!("Pack index file not found: {:?}", index_file_path))); }
            let index_file = File::open(&index_file_path)?;
            let pack_index = crate::packset::PackIndex::new(BufReader::new(index_file))?;
            let pack_object_info = pack_index.objects.iter().find(|obj_info| {
                obj_info.sha1 == blob_loc.blob_identifier
            }).ok_or_else(|| Error::NotFound(format!( "Blob {} not found in pack index {:?}", blob_loc.blob_identifier, index_file_path )))?; // Corrected to NotFound
            let mut pack_file = File::open(&pack_file_path)?;
            pack_file.seek(SeekFrom::Start(pack_object_info.offset as u64))?; // Ensure SeekFrom is used correctly
            let mut object_slice = vec![0u8; pack_object_info.data_len];
            pack_file.read_exact(&mut object_slice)?;
            object_slice
        } else {
            let standalone_path = self.base_path.join(blob_loc.relative_path.trim_start_matches('/'));
            if !standalone_path.exists() { return Err(Error::Io(format!("Standalone blob not found: {:?}", standalone_path))); }
            fs::read(standalone_path)?
        };

        let decrypted_bytes = if self.config.is_encrypted {
            if !raw_object_bytes.starts_with(Arq7EncryptedObject::HEADER) {
                return Err(Error::InvalidData(format!( "Expected ARQO header for blob {} (path: {}) but not found.", blob_loc.blob_identifier, blob_loc.relative_path)));
            }
            let arqo = Arq7EncryptedObject::from_bytes(&raw_object_bytes)?;
            arqo.decrypt(self.keys.as_ref().ok_or(Error::Encryption("Missing keys for encrypted blob".to_string()))?)?
        } else {
            if raw_object_bytes.starts_with(Arq7EncryptedObject::HEADER) {
                 return Err(Error::InvalidData(format!( "Unexpected ARQO header for unencrypted blob {} (path: {})", blob_loc.blob_identifier, blob_loc.relative_path)));
            }
            raw_object_bytes
        };

        let ct = match blob_loc.compression_type {
            0 => crate::compression::CompressionType::None,
            1 => crate::compression::CompressionType::Gzip,
            2 => crate::compression::CompressionType::LZ4,
            _ => return Err(Error::InvalidData(format!("Unknown compression type: {}", blob_loc.compression_type))),
        };
        crate::compression::CompressionType::decompress(&decrypted_bytes, ct)
    }

    pub fn get_tree_bin(&self, blob_loc: &BlobLoc) -> Result<TreeBin> {
        let tree_data_bytes = self.fetch_blob_data_and_decompress(blob_loc)?;
        TreeBin::from_reader(&mut Cursor::new(tree_data_bytes))
    }

    pub fn get_root_tree_for_record(&self, record: &BackupRecord) -> Result<TreeBin> {
        if record.copied_from_commit && record.arq5_tree_blob_key.is_some() {
            return Err(Error::NotSupported("Record is an Arq5 commit, requires Arq5 parsing logic.".into()));
        }
        let root_node_json = record.node.as_ref().ok_or_else(|| Error::InvalidData("BackupRecord has no root node JSON.".into()))?;
        if !root_node_json.is_tree { return Err(Error::InvalidData("BackupRecord root node is not a tree.".into())); }
        let tree_blob_loc = root_node_json.tree_blob_loc.as_ref().ok_or_else(|| Error::InvalidData("Root tree node has no BlobLoc.".into()))?;
        self.get_tree_bin(tree_blob_loc)
    }

    pub fn resolve_path_to_node(&self, record: &BackupRecord, path_str: &str) -> Result<NodeBin> {
        let mut current_tree = self.get_root_tree_for_record(record)?;
        let path_normalized = PathBuf::from(path_str);
        let components: Vec<&str> = path_normalized.iter().map(|os_str| os_str.to_str().unwrap_or("")).filter(|s| !s.is_empty() && *s != "." && *s != "/").collect();
        if components.is_empty() {
             return Err(Error::Input("Path cannot be empty or root for resolve_path_to_node. Use get_root_tree_for_record and its associated Node for root.".into()));
        }
        let mut target_node: Option<NodeBin> = None;
        for (i, component) in components.iter().enumerate() {
            let child_node = current_tree.child_nodes_by_name.get(*component).ok_or_else(|| Error::NotFound(format!("Path component '{}' not found in tree.", component)))?;
            if i == components.len() - 1 { target_node = Some(child_node.clone()); break; }
            else {
                if !child_node.is_tree { return Err(Error::InvalidData(format!("Path component '{}' is a file, not a directory, but more path components remain.", component))); }
                let tree_blob_loc = child_node.tree_blob_loc.as_ref().ok_or_else(|| Error::InvalidData(format!("Intermediate directory '{}' has no tree_blob_loc.", component)))?;
                current_tree = self.get_tree_bin(tree_blob_loc)?;
            }
        }
        target_node.ok_or_else(|| Error::NotFound(format!("Path '{}' not resolved.", path_str)))
    }

    pub fn list_directory_from_node(&self, dir_node_bin: &NodeBin) -> Result<Vec<(String, NodeBin)>> {
        if !dir_node_bin.is_tree { return Err(Error::InvalidData("Cannot list contents: provided NodeBin is not a directory.".into())); }
        let tree_blob_loc = dir_node_bin.tree_blob_loc.as_ref().ok_or_else(|| Error::InvalidData("Directory NodeBin has no tree_blob_loc.".into()))?;
        let tree_bin = self.get_tree_bin(tree_blob_loc)?;
        Ok(tree_bin.child_nodes_by_name.into_iter().collect())
    }

    pub fn read_file_content_from_node(&self, file_node_bin: &NodeBin) -> Result<Vec<u8>> {
        if file_node_bin.is_tree { return Err(Error::InvalidData("Cannot read content: provided NodeBin is a directory.".into())); }
        let mut file_content = Vec::with_capacity(file_node_bin.item_size as usize);
        for blob_loc in &file_node_bin.data_blob_locs {
            let chunk_data = self.fetch_blob_data_and_decompress(blob_loc)?;
            file_content.extend_from_slice(&chunk_data);
        }
        if file_content.len() != file_node_bin.item_size as usize {
             eprintln!( "Warning: Final file content size {} differs from NodeBin item_size {}", file_content.len(), file_node_bin.item_size );
        }
        Ok(file_content)
    }
}
