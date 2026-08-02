use std::collections::HashMap;

fn main() {
    let mut map = HashMap::new();
    map.insert("a".to_string(), "b".to_string());
    println!("{:?}", map);
}
