use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;

// Dummy types mimicking the real types
#[derive(Clone)]
struct BackupFolder;
struct GenericBackupRecord;

fn bench_insertion(c: &mut Criterion) {
    // Generate some test data
    let mut results = Vec::new();
    for i in 0..10_000 {
        let uuid = format!("uuid-{}", i);
        // Vary the options to cover all paths
        let folder = if i % 2 == 0 { Some(BackupFolder) } else { None };
        let records = if i % 3 != 0 {
            Some(vec![GenericBackupRecord])
        } else {
            None
        };
        results.push((uuid, folder, records));
    }

    c.bench_function("backup_set_insert_optimized", |b| {
        b.iter(|| {
            let mut backup_folder_configs: HashMap<String, BackupFolder> = HashMap::new();
            let mut backup_records: HashMap<String, Vec<GenericBackupRecord>> = HashMap::new();

            for (folder_uuid, folder_config_opt, records_opt) in &results {
                let folder_uuid = folder_uuid.clone(); // Mimicking the clone from the original `results?` iterator producing owned strings
                let folder_config_opt = folder_config_opt.clone();
                let owned_records = if records_opt.is_some() {
                    Some(vec![GenericBackupRecord])
                } else {
                    None
                };

                // Optimized logic:
                match (folder_config_opt, owned_records) {
                    (Some(folder_config), Some(records)) => {
                        backup_folder_configs.insert(folder_uuid.clone(), folder_config);
                        backup_records.insert(folder_uuid, records);
                    }
                    (Some(folder_config), None) => {
                        backup_folder_configs.insert(folder_uuid, folder_config);
                    }
                    (None, Some(records)) => {
                        backup_records.insert(folder_uuid, records);
                    }
                    (None, None) => {}
                }
            }
            black_box((backup_folder_configs, backup_records));
        })
    });
}

criterion_group!(benches, bench_insertion);
criterion_main!(benches);
