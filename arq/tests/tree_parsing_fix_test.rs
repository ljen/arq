use arq::tree::Tree;
use std::fs;
use std::path::Path;

#[test]
fn test_load_arq7_new_treepacks() {
    let treepacks_dir = Path::new("/Users/ljensen/Projects/2025-06-arq/arq/tests/treepacks/arq7_new");
    let paths = fs::read_dir(treepacks_dir).unwrap();

    for path in paths {
        let path = path.unwrap().path();
        if path.is_file() {
            let data = fs::read(&path).unwrap();
            let tree = Tree::from_arq7_binary_data(&data);
            assert!(tree.is_ok(), "Failed to parse tree at {:?}", path);
        }
    }
}