use criterion::{criterion_group, criterion_main, Criterion};

use arq::compression::CompressionType;
use arq::tree::Tree;
use rayon::prelude::*;
use std::fs;
use std::path::Path;

fn load_treepacks_from_dir_old(dir: &str) {
    let treepacks_dir = Path::new(dir);
    let paths = fs::read_dir(treepacks_dir).unwrap();

    for path in paths {
        let path = path.unwrap().path();
        if path.is_file() {
            let data = fs::read(&path).unwrap();

            if data.len() >= 5 && &data[0..5] == b"TreeV" {
                let mut parsed = false;
                if let Ok(_tree) = Tree::new_arq5(&data, CompressionType::None) {
                    parsed = true;
                } else if let Ok(_tree) = Tree::new_arq5(&data, CompressionType::Gzip) {
                    parsed = true;
                }
                assert!(parsed, "Failed to parse Arq5 tree at {:?}", path);
            } else {
                let tree = Tree::from_arq7_binary_data(&data);
                assert!(tree.is_ok(), "Failed to parse Arq7 tree at {:?}", path);
            }
        }
    }
}

fn load_treepacks_from_dir_threaded(dir: &str) {
    let treepacks_dir = Path::new(dir);
    let paths: Vec<_> = fs::read_dir(treepacks_dir)
        .unwrap()
        .filter_map(|r| r.ok())
        .map(|r| r.path())
        .filter(|p| p.is_file())
        .collect();

    paths.into_par_iter().for_each(|path| {
        let data = fs::read(&path).unwrap();
        if data.len() >= 5 && &data[0..5] == b"TreeV" {
            let mut parsed = false;
            if let Ok(_tree) = Tree::new_arq5(&data, CompressionType::None) {
                parsed = true;
            } else if let Ok(_tree) = Tree::new_arq5(&data, CompressionType::Gzip) {
                parsed = true;
            }
            assert!(parsed, "Failed to parse Arq5 tree at {:?}", path);
        } else {
            let tree = Tree::from_arq7_binary_data(&data);
            assert!(tree.is_ok(), "Failed to parse Arq7 tree at {:?}", path);
        }
    });
}

fn bench_load_treepacks(c: &mut Criterion) {
    c.bench_function("old_impl", |b| {
        b.iter(|| {
            load_treepacks_from_dir_old("./tests/treepacks/arq7_new");
        })
    });
    c.bench_function("threaded_impl", |b| {
        b.iter(|| {
            load_treepacks_from_dir_threaded("./tests/treepacks/arq7_new");
        })
    });
}

criterion_group!(benches, bench_load_treepacks);
criterion_main!(benches);
