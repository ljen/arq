use std::cell::OnceCell;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cell: OnceCell<HashMap<String, String>> = OnceCell::new();
    let res = cell.get_or_try_init(|| {
        let mut map = HashMap::new();
        map.insert("a".to_string(), "b".to_string());
        Ok::<_, Box<dyn std::error::Error>>(map)
    })?;
    println!("{:?}", res);
    Ok(())
}
