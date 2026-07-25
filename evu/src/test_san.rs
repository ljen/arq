fn sanitize_filename(name: &str) -> String {
    name.replace(|c: char| c == '/' || c == '\\' || c == ':', "_")
}
fn main() {
    let inputs = vec![
        "..",
        ".",
        "../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\System32",
        "foo/bar",
        "a/b/c",
        "normal_file.txt",
        "C:passwd",
    ];
    for p in inputs {
        println!("{} -> {}", p, sanitize_filename(p));
    }
}
