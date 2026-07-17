use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tempfile::tempdir;

fn setup_dummy_dir(n_files: usize) -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    for i in 0..n_files {
        let file_path = dir.path().join(format!("file_{}.index", i));
        let mut file = File::create(file_path).unwrap();
        file.write_all(b"dummy index content").unwrap();
    }
    dir
}

fn benchmark_read_dir_uncached(c: &mut Criterion) {
    let dir = setup_dummy_dir(100);
    let path = dir.path().to_path_buf();

    // Simulate iterating multiple blobs
    c.bench_function("read_dir_uncached", |b| {
        b.iter(|| {
            let mut matches = 0;
            for _blob in 0..10 {
                // Simulate 10 data_blob_locs
                for entry in fs::read_dir(&path).unwrap() {
                    let entry = entry.unwrap();
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if fname.ends_with(".index") {
                        matches += 1;
                    }
                }
            }
            black_box(matches);
        })
    });
}

fn benchmark_read_dir_cached(c: &mut Criterion) {
    let dir = setup_dummy_dir(100);
    let path = dir.path().to_path_buf();

    c.bench_function("read_dir_cached", |b| {
        b.iter(|| {
            let mut matches = 0;
            let mut cached_entries = Vec::new();
            for entry in fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.ends_with(".index") {
                    cached_entries.push(fname);
                }
            }

            for _blob in 0..10 {
                // Simulate 10 data_blob_locs
                for fname in &cached_entries {
                    matches += 1;
                }
            }
            black_box(matches);
        })
    });
}

criterion_group!(
    benches,
    benchmark_read_dir_uncached,
    benchmark_read_dir_cached
);
criterion_main!(benches);
