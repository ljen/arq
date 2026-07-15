use std::fs;

use crate::error::Result;
use crate::utils;

use arq::computer::ComputerInfo;

pub fn get_computers(path: &str) -> Result<Vec<ComputerInfo>> {
    let mut computers = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry.unwrap();
        let reader = utils::get_file_reader(&entry.path().join("computerinfo"))?;
        computers.push(ComputerInfo::new(reader, entry.file_name().into_string()?)?);
    }
    Ok(computers)
}

pub fn show(path: &str) -> Result<()> {
    println!("Computers\n---------");
    for computer in get_computers(path)?.iter() {
        println!(
            "> [{}] ({}@{})",
            computer.uuid, computer.user_name, computer.computer_name,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_get_computers_invalid_path() {
        let result = get_computers("/nonexistent/path/that/should/fail");
        assert!(result.is_err(), "Expected an error for an invalid path");
    }

    #[test]
    fn test_show_invalid_path() {
        let result = show("/nonexistent/path/that/should/fail");
        assert!(
            result.is_err(),
            "Expected an error for an invalid path in show"
        );
    }

    #[test]
    fn test_show_valid_path() {
        let temp_dir = tempdir().unwrap();
        let computer_dir = temp_dir.path().join("1234-5678");
        std::fs::create_dir(&computer_dir).unwrap();

        let mut file = std::fs::File::create(computer_dir.join("computerinfo")).unwrap();
        let raw = "<plist><dict><key>userName</key><string>testuser</string><key>computerName</key><string>testcomputer</string></dict></plist>";
        file.write_all(raw.as_bytes()).unwrap();

        let result = show(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok(), "Expected Ok for a valid path");
    }
}
