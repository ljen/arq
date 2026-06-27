use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_path_joining(c: &mut Criterion) {
    let relative_path = "some/very/long/relative/path";
    let child_name = "and_a_child_name.txt";
    let child_name_string = String::from(child_name);

    c.bench_function("path_join_clone_empty", |b| {
        let rel_empty = "";
        b.iter(|| {
            let _child_path = if rel_empty.is_empty() {
                child_name_string.clone()
            } else {
                format!("{}/{}", rel_empty, child_name_string)
            };
        })
    });

    c.bench_function("path_join_clone_nonempty", |b| {
        let rel_nonempty = relative_path;
        b.iter(|| {
            let _child_path = if rel_nonempty.is_empty() {
                child_name_string.clone()
            } else {
                format!("{}/{}", rel_nonempty, child_name_string)
            };
        })
    });

    c.bench_function("path_join_cow_empty", |b| {
        let rel_empty = "";
        b.iter(|| {
            let _child_path = if rel_empty.is_empty() {
                std::borrow::Cow::Borrowed(child_name_string.as_str())
            } else {
                std::borrow::Cow::Owned(format!("{}/{}", rel_empty, child_name_string))
            };
        })
    });

    c.bench_function("path_join_cow_nonempty", |b| {
        let rel_nonempty = relative_path;
        b.iter(|| {
            let _child_path = if rel_nonempty.is_empty() {
                std::borrow::Cow::Borrowed(child_name_string.as_str())
            } else {
                std::borrow::Cow::Owned(format!("{}/{}", rel_nonempty, child_name_string))
            };
        })
    });
}

criterion_group!(benches, benchmark_path_joining);
criterion_main!(benches);
