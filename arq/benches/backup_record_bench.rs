use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json;

// This bench compares parsing from String vs parsing from slice directly
fn bench_backup_record_parsing(c: &mut Criterion) {
    // We'll construct a realistic JSON payload for testing
    let json_data = r#"{
        "backupFolderUUID": "CEAA7545-3174-4E7C-A580-3D10BAED153E",
        "diskIdentifier": "ROOT",
        "storageClass": "STANDARD",
        "version": 100,
        "backupPlanUUID": "D1154AC6-01EB-41FE-B115-114464350B92",
        "backupRecordErrors": [],
        "copiedFromSnapshot": false,
        "copiedFromCommit": false,
        "node": {
            "is_dir": false,
            "mtime_sec": 1234567890,
            "mtime_nsec": 0,
            "ctime_sec": 1234567890,
            "ctime_nsec": 0,
            "mode": 33188,
            "flags": 0,
            "finder_flags": 0,
            "extended_finder_flags": 0,
            "st_dev": 0,
            "st_ino": 0,
            "st_nlink": 0,
            "st_uid": 501,
            "st_gid": 20,
            "st_rdev": 0,
            "st_size": 1024,
            "st_blocks": 8,
            "st_blksize": 4096,
            "acl": null,
            "xattrs": null,
            "data_blob_keys": null,
            "tree_blob_keys": null
        }
    }"#;
    let byte_data = json_data.as_bytes().to_vec();

    c.bench_function("parse_from_string", |b| {
        b.iter(|| {
            let data = black_box(&byte_data);
            let json_str = String::from_utf8(data.clone()).unwrap();
            let _: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        })
    });

    c.bench_function("parse_from_slice", |b| {
        b.iter(|| {
            let data = black_box(&byte_data);
            let _: serde_json::Value = serde_json::from_slice(data).unwrap();
        })
    });
}

criterion_group!(benches, bench_backup_record_parsing);
criterion_main!(benches);
