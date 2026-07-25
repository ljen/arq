use std::path::{Path, Component};

fn is_safe(path: &str) -> bool {
    let p = Path::new(path);
    if p.is_absolute() { return false; }
    for comp in p.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

fn sanitize(path: &str) -> String {
    path.replace(|c: char| c == '/' || c == '\\' || c == ':', "_")
}

fn main() {
    let bad = vec![
        "../..",
        "../../etc",
        "/etc/passwd",
        "C:\\Windows\\System32",
        "\\\\server\\share\\file",
        "a/b/../c",
        "..foo",
        "foo..",
        "~/.ssh/id_rsa",
        "C:passwd",
    ];
    for b in bad {
        let os_str_val = std::path::Path::new(b)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("invalid_node_name"));
        let os_str = os_str_val.to_string_lossy();
        let safe = sanitize(&os_str);
        println!("{} -> {:?} -> {}", b, os_str_val, safe);
    }
}
