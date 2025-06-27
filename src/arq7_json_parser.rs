use crate::arq7_types::{BackupConfig, BackupFolders, BackupFolderMeta, BackupPlan, BackupRecord};
use crate::error::ArqError;
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;
use lz4_flex;
use byteorder; // Added

pub fn parse_backup_config<P: AsRef<Path>>(path: P) -> Result<BackupConfig, ArqError> {
    let file = File::open(path).map_err(|e| ArqError::Io(e))?;
    let reader = BufReader::new(file);
    let config: BackupConfig = serde_json::from_reader(reader)
        .map_err(|e| ArqError::Json(e))?;
    Ok(config)
}

pub fn parse_backup_folders<P: AsRef<Path>>(path: P) -> Result<BackupFolders, ArqError> {
    let file = File::open(path).map_err(|e| ArqError::Io(e))?;
    let reader = BufReader::new(file);
    let folders: BackupFolders = serde_json::from_reader(reader)
        .map_err(|e| ArqError::Json(e))?;
    Ok(folders)
}

pub fn parse_backup_plan<P: AsRef<Path>>(path: P) -> Result<BackupPlan, ArqError> {
    let file = File::open(path).map_err(|e| ArqError::Io(e))?;
    let reader = BufReader::new(file);
    let plan: BackupPlan = serde_json::from_reader(reader)
        .map_err(|e| ArqError::Json(e))?;
    Ok(plan)
}

pub fn parse_backup_folder_meta<P: AsRef<Path>>(path: P) -> Result<BackupFolderMeta, ArqError> {
    let file = File::open(path).map_err(|e| ArqError::Io(e))?;
    let reader = BufReader::new(file);
    let meta: BackupFolderMeta = serde_json::from_reader(reader)
        .map_err(|e| ArqError::Json(e))?;
    Ok(meta)
}

pub fn parse_backup_record<P: AsRef<Path>>(path: P) -> Result<BackupRecord, ArqError> {
    let mut file = File::open(path).map_err(|e| ArqError::Io(e))?;

    // Read the entire file. Backup records are LZ4 compressed.
    // "Data described in this document as “LZ4-compressed” is stored as a
    // 4-byte big-endian length followed by the compressed data in LZ4 block format."
    let mut compressed_data_with_prefix = Vec::new();
    file.read_to_end(&mut compressed_data_with_prefix).map_err(ArqError::Io)?;

    if compressed_data_with_prefix.len() < 4 {
        return Err(ArqError::Generic("Backup record file is too short to contain LZ4 length prefix.".to_string()));
    }

    // Manually read big-endian u32 original size
    let mut cursor = std::io::Cursor::new(&compressed_data_with_prefix[0..4]);
    let original_size = byteorder::ReadBytesExt::read_u32::<byteorder::BigEndian>(&mut cursor)
        .map_err(ArqError::Io)? as usize;

    let actual_compressed_data = &compressed_data_with_prefix[4..];

    // Using lz4_flex::block::decompress for raw LZ4 blocks
    let mut decompressed_data_vec = vec![0u8; original_size];
    let bytes_decompressed = lz4_flex::block::decompress_into(actual_compressed_data, &mut decompressed_data_vec)
        .map_err(|e| ArqError::Decompression(format!("LZ4 block decompress_into error for backup record: {:?}, expected original size: {}", e, original_size)))?;

    if bytes_decompressed != original_size {
        return Err(ArqError::Decompression(format!("LZ4 decompressed size mismatch for backup record. Expected {}, got {}", original_size, bytes_decompressed)));
    }

    // Now parse the decompressed data as JSON.
    let record: BackupRecord = serde_json::from_slice(&decompressed_data_vec)
        .map_err(|e| ArqError::Json(e))?;

    Ok(record)
}
