use std::path::Path;

fn main() {
    let p1 = Path::new("..").file_name();
    let p2 = Path::new(".").file_name();
    let p3 = Path::new("/").file_name();
    let p4 = Path::new("C:\\").file_name();
    println!("{:?} {:?} {:?} {:?}", p1, p2, p3, p4);
}
