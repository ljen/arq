use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::io::Cursor;
use byteorder::{ReadBytesExt, NetworkEndian};

fn bench_cursor_clone(c: &mut Criterion) {
    let mut fanout: Vec<Vec<u8>> = vec![vec![0; 4]; 256];
    fanout[255] = vec![0, 0, 0, 42];

    c.bench_function("cursor_clone", |b| b.iter(|| {
        let cloned = fanout[255].clone();
        let count_vec = black_box(&cloned);
        let mut rdr = Cursor::new(count_vec);
        black_box(rdr.read_u32::<NetworkEndian>().unwrap());
    }));
}

fn bench_cursor_no_clone(c: &mut Criterion) {
    let mut fanout: Vec<Vec<u8>> = vec![vec![0; 4]; 256];
    fanout[255] = vec![0, 0, 0, 42];

    c.bench_function("cursor_no_clone", |b| b.iter(|| {
        let count_vec = black_box(&fanout[255]);
        let mut rdr = Cursor::new(count_vec);
        black_box(rdr.read_u32::<NetworkEndian>().unwrap());
    }));
}

criterion_group!(benches, bench_cursor_clone, bench_cursor_no_clone);
criterion_main!(benches);
