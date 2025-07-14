use arq::tree::Tree;
use arq::compression::CompressionType;
use std::fs;
use std::path::Path;

fn load_treepacks_from_dir(dir: &str) {
    let treepacks_dir = Path::new(dir);
    let paths = fs::read_dir(treepacks_dir).unwrap();

    for path in paths {
        let path = path.unwrap().path();
        if path.is_file() {
            let data = fs::read(&path).unwrap();
            
            // Check the first few bytes to determine format
            // Arq5 trees start with "TreeV"
            if data.len() >= 5 && &data[0..5] == b"TreeV" {
                let mut parsed = false;
                // Try parsing as Arq5 with no compression
                if let Ok(_tree) = Tree::new_arq5(&data, CompressionType::None) {
                    parsed = true;
                } else if let Ok(_tree) = Tree::new_arq5(&data, CompressionType::Gzip) {
                    // If no compression fails, try Gzip
                    parsed = true;
                }
                assert!(parsed, "Failed to parse Arq5 tree at {:?}", path);
            } else {
                // Assume Arq7 if not Arq5
                let tree = Tree::from_arq7_binary_data(&data);
                assert!(tree.is_ok(), "Failed to parse Arq7 tree at {:?}", path);
            }
        }
    }
}

#[test]
fn test_load_arq7_new_treepacks() {
    load_treepacks_from_dir("./tests/treepacks/arq7_new");
}

#[test]
fn test_load_arq7_old_treepacks() {
    load_treepacks_from_dir("./tests/treepacks/arq7_old");
}