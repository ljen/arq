use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn mock_load(records: &mut Vec<String>, count: usize) {
    for i in 0..count {
        records.push(format!("item {}", i));
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("vec_new_in_loop", |b| {
        b.iter(|| {
            let mut map = std::collections::HashMap::new();
            for i in 0..100 {
                let mut folder_records = Vec::new();
                mock_load(&mut folder_records, 50);
                if !folder_records.is_empty() {
                    map.insert(i, folder_records);
                }
            }
            black_box(map);
        })
    });

    c.bench_function("vec_append", |b| {
        b.iter(|| {
            let mut map = std::collections::HashMap::new();
            let mut hoisted_records = Vec::new();
            for i in 0..100 {
                hoisted_records.clear();
                mock_load(&mut hoisted_records, 50);
                if !hoisted_records.is_empty() {
                    let mut final_records = Vec::with_capacity(hoisted_records.len());
                    final_records.append(&mut hoisted_records);
                    map.insert(i, final_records);
                }
            }
            black_box(map);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
