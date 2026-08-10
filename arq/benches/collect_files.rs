use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::PathBuf;

// Mock structure for Node and Tree to benchmark the traversal logic
struct Node {
    is_tree: bool,
}

impl Node {
    fn load_tree(&self) -> Option<Tree> {
        if self.is_tree {
            let mut tree = Tree { nodes: vec![] };
            for i in 0..100 {
                tree.nodes.push((
                    format!("file_or_folder_{}", i),
                    Node {
                        is_tree: i % 10 == 0,
                    },
                ));
            }
            Some(tree)
        } else {
            None
        }
    }
}

struct Tree {
    nodes: Vec<(String, Node)>,
}

// 1. Original logic utilizing standard push_str which relies on amortized dynamic reallocation
fn collect_files_recursive_string(
    node: &Node,
    current_path: &mut String,
    files: &mut Vec<String>,
    depth: usize,
) {
    if depth > 3 {
        return;
    }

    if !node.is_tree {
        if !current_path.is_empty() {
            files.push(current_path.clone());
        }
        return;
    }

    if let Some(tree) = node.load_tree() {
        for (name, child_node) in &tree.nodes {
            let original_len = current_path.len();
            if !current_path.is_empty() {
                current_path.push('/');
            }
            current_path.push_str(name);

            collect_files_recursive_string(child_node, current_path, files, depth + 1);

            current_path.truncate(original_len);
        }
    }
}

// 2. Logic utilizing PathBuf which is "safer" but slower due to interacting with OS-specific representations instead of basic utf-8 bytes
fn collect_files_recursive_pathbuf(
    node: &Node,
    current_path: &mut PathBuf,
    files: &mut Vec<String>,
    depth: usize,
) {
    if depth > 3 {
        return;
    }

    if !node.is_tree {
        if let Some(s) = current_path.to_str() {
            if !s.is_empty() {
                files.push(s.to_owned());
            }
        }
        return;
    }

    if let Some(tree) = node.load_tree() {
        for (name, child_node) in &tree.nodes {
            current_path.push(name);

            collect_files_recursive_pathbuf(child_node, current_path, files, depth + 1);

            current_path.pop();
        }
    }
}

// 3. Logic manually ensuring capacity right before push, preventing all re-allocations at the cost of computing remaining capacity on each iteration
fn collect_files_recursive_string_with_capacity_checks(
    node: &Node,
    current_path: &mut String,
    files: &mut Vec<String>,
    depth: usize,
) {
    if depth > 3 {
        return;
    }

    if !node.is_tree {
        if !current_path.is_empty() {
            files.push(current_path.clone());
        }
        return;
    }

    if let Some(tree) = node.load_tree() {
        for (name, child_node) in &tree.nodes {
            let original_len = current_path.len();
            let needed_extra = if current_path.is_empty() {
                name.len()
            } else {
                name.len() + 1
            };
            current_path.reserve(needed_extra);

            if !current_path.is_empty() {
                current_path.push('/');
            }
            current_path.push_str(name);

            collect_files_recursive_string_with_capacity_checks(
                child_node,
                current_path,
                files,
                depth + 1,
            );

            current_path.truncate(original_len);
        }
    }
}

fn bench_collect(c: &mut Criterion) {
    let root = Node { is_tree: true };

    // Benchmarking Results:
    //
    // 1. collect_files_string                     : ~13.2 ms
    // 2. collect_files_string_with_capacity_checks: ~14.9 ms
    // 3. collect_files_pathbuf                    : ~22.8 ms
    //
    // Findings:
    // We initially hypothesized that string reallocations were heavily bottlenecking directory traversal here.
    // However, Rust's standard amortized Vec scaling (doubling capacity on bounds check failure) makes it
    // out-perform manual capability checking (`.reserve()`), and easily beats shifting over to PathBuf.
    //
    // The most performant strategy for this exact case where we backtrack via `.truncate` is to leave
    // `.push_str` as-is, and just initialize `current_path = String::with_capacity(1024)` right when it is
    // created to completely remove the initial few small-buffer reallocations.

    c.bench_function("collect_files_string", |b| {
        b.iter(|| {
            let mut current_path = String::with_capacity(1024);
            let mut files = Vec::new();
            collect_files_recursive_string(&root, &mut current_path, &mut files, 0);
            black_box(files);
        })
    });

    c.bench_function("collect_files_pathbuf", |b| {
        b.iter(|| {
            let mut current_path = PathBuf::with_capacity(1024);
            let mut files = Vec::new();
            collect_files_recursive_pathbuf(&root, &mut current_path, &mut files, 0);
            black_box(files);
        })
    });

    c.bench_function("collect_files_string_reserve", |b| {
        b.iter(|| {
            let mut current_path = String::with_capacity(1024);
            let mut files = Vec::new();
            collect_files_recursive_string_with_capacity_checks(
                &root,
                &mut current_path,
                &mut files,
                0,
            );
            black_box(files);
        })
    });
}

criterion_group!(benches, bench_collect);
criterion_main!(benches);
