extern crate evu;

use std::path::Path; // Required for Path::new

fn main() -> Result<(), evu::error::Error> {
    let matches = evu::cli::parse_flags();

    // Global arguments (relevant for Arq7 or if we make Arq5 path/password global too)
    let global_path_opt = matches.value_of("path");
    let global_password_opt = matches.value_of("password");

    match matches.subcommand() {
        ("show", Some(cmd)) => {
            let arq5_path = global_path_opt.ok_or_else(|| evu::error::Error::CliInputError("Path is required for Arq5 'show' commands".to_string()))?;
            match cmd.subcommand() {
                ("computers", Some(_)) => evu::computers::show(arq5_path)?,
                ("folders", Some(c)) => {
                    evu::folders::show(arq5_path, c.value_of("computer").unwrap())?
                }
                ("tree", Some(c)) => evu::tree::show(
                    arq5_path,
                    c.value_of("computer").unwrap(),
                    c.value_of("folder").unwrap(),
                )?,
                _ => println!("Invalid 'show' subcommand. Use --help for details."),
            }
        }
        ("restore", Some(cmd)) => {
            let arq5_path = global_path_opt.ok_or_else(|| evu::error::Error::CliInputError("Path is required for Arq5 'restore' command".to_string()))?;
            evu::recovery::restore_file(
                arq5_path,
                cmd.value_of("computer").unwrap(),
                cmd.value_of("folder").unwrap(),
                cmd.value_of("FILEPATH").unwrap(),
            )?
        }
        ("arq7", Some(arq7_matches)) => {
            // Arq7 commands have their own --path and --password options,
            // but we can also use the global ones if the specific ones are not provided.
            let arq7_path_str = arq7_matches.value_of("path")
                .or(global_path_opt) // Fallback to global path
                .ok_or_else(|| evu::error::Error::CliInputError("Path to Arq7 backup set is required.".to_string()))?;
            let arq7_path = Path::new(arq7_path_str);

            let arq7_password = arq7_matches.value_of("password")
                .or(global_password_opt); // Fallback to global password


            match arq7_matches.subcommand() {
                ("show-records", Some(_)) => {
                    evu::arq7_handler::list_backup_records(arq7_path, arq7_password)?;
                }
                ("show-file-versions", Some(sub_matches)) => {
                    let file_path = sub_matches.value_of("file").unwrap();
                    evu::arq7_handler::list_file_versions(arq7_path, file_path, arq7_password)?;
                }
                ("show-folder-versions", Some(sub_matches)) => {
                    let folder_path = sub_matches.value_of("folder").unwrap();
                    evu::arq7_handler::list_folder_versions(arq7_path, folder_path, arq7_password)?;
                }
                ("restore-record", Some(sub_matches)) => {
                    let record_id = sub_matches.value_of("record").unwrap();
                    let dest_str = sub_matches.value_of("destination").unwrap();
                    evu::arq7_handler::restore_full_record(arq7_path, record_id, Path::new(dest_str), arq7_password)?;
                }
                ("restore-file", Some(sub_matches)) => {
                    let record_id = sub_matches.value_of("record").unwrap();
                    let file_path = sub_matches.value_of("file").unwrap();
                    let dest_str = sub_matches.value_of("destination").unwrap();
                    evu::arq7_handler::restore_specific_file_from_record(arq7_path, record_id, file_path, Path::new(dest_str), arq7_password)?;
                }
                ("restore-folder", Some(sub_matches)) => {
                    let record_id = sub_matches.value_of("record").unwrap();
                    let folder_path = sub_matches.value_of("folder").unwrap();
                    let dest_str = sub_matches.value_of("destination").unwrap();
                    evu::arq7_handler::restore_specific_folder_from_record(arq7_path, record_id, folder_path, Path::new(dest_str), arq7_password)?;
                }
                ("restore-all-folder-versions", Some(sub_matches)) => {
                    let folder_path = sub_matches.value_of("folder").unwrap();
                    let dest_root_str = sub_matches.value_of("destination-root").unwrap();
                    evu::arq7_handler::restore_all_folder_versions(arq7_path, folder_path, Path::new(dest_root_str), arq7_password)?;
                }
                _ => println!("Invalid 'arq7' subcommand. Use --help for details."),
            }
        }
        _ => {
            // If no subcommand is given, or an unknown one, Clap usually handles this.
            // But as a fallback, or if only global options were given:
            println!("No command specified or unknown command. Use --help for available commands.");
            // Optionally, if only --path and --password were given, you might want to auto-detect
            // and show some default info, but that's more complex.
        }
    }
    Ok(())
}
