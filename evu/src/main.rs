extern crate evu;

use std::path::Path;
use evu::autodetect::{detect_version, ArqVersion};

fn main() -> Result<(), evu::error::Error> {
    let matches = evu::cli::parse_flags();

    evu::utils::initialize_debug_from_args(&matches);

    let global_path_str = matches.value_of("path").ok_or_else(|| evu::error::Error::CliInputError("Path is required.".to_string()))?;
    let global_path = Path::new(global_path_str);
    let global_password = matches.value_of("password");

    let version = detect_version(global_path)?;

    match matches.subcommand() {
        ("show", Some(cmd)) => {
            match version {
                ArqVersion::Arq5 => {
                    let computer_uuid = global_path.file_name().unwrap().to_str().unwrap();
                    match cmd.subcommand() {
                        ("folders", Some(_)) => {
                            evu::folders::show(global_path_str, computer_uuid, matches.value_of("password"))?
                        }
                        ("tree", Some(c)) => evu::tree::show(
                            global_path_str,
                            computer_uuid,
                            c.value_of("folder").unwrap(),
                            matches.value_of("password"),
                        )?,
                        _ => println!("Invalid 'show' subcommand for Arq 5. Use --help for details."),
                    }
                },
                ArqVersion::Arq7 => {
                    match cmd.subcommand() {
                        ("records", Some(_)) => {
                            evu::arq7_handler::list_backup_records(global_path, global_password)?;
                        },
                        ("file-versions", Some(sub_matches)) => {
                            let file_path = sub_matches.value_of("file").unwrap();
                            evu::arq7_handler::list_file_versions(global_path, file_path, global_password)?;
                        },
                        ("folder-versions", Some(sub_matches)) => {
                            let folder_path = sub_matches.value_of("folder").unwrap();
                            evu::arq7_handler::list_folder_versions(global_path, folder_path, global_password)?;
                        },
                        _ => println!("Invalid 'show' subcommand for Arq 7. Use --help for details."),
                    }
                }
            }
        }
        ("restore", Some(cmd)) => {
            match version {
                ArqVersion::Arq5 => {
                    let computer_uuid = global_path.file_name().unwrap().to_str().unwrap();
                    evu::recovery::restore_file(
                        global_path_str,
                        computer_uuid,
                        cmd.value_of("folder").unwrap(),
                        cmd.value_of("FILEPATH").unwrap(),
                    )?
                },
                ArqVersion::Arq7 => {
                    match cmd.subcommand() {
                        ("record", Some(sub_matches)) => {
                            let record_id = sub_matches.value_of("record").unwrap();
                            let dest_str = sub_matches.value_of("destination").unwrap();
                            evu::arq7_handler::restore_full_record(global_path, record_id, Path::new(dest_str), global_password)?;
                        },
                        ("file", Some(sub_matches)) => {
                            let record_id = sub_matches.value_of("record").unwrap();
                            let file_path = sub_matches.value_of("file").unwrap();
                            let dest_str = sub_matches.value_of("destination").unwrap();
                            evu::arq7_handler::restore_specific_file_from_record(global_path, record_id, file_path, Path::new(dest_str), global_password)?;
                        },
                        ("folder", Some(sub_matches)) => {
                            let record_id = sub_matches.value_of("record").unwrap();
                            let folder_path = sub_matches.value_of("folder").unwrap();
                            let dest_str = sub_matches.value_of("destination").unwrap();
                            evu::arq7_handler::restore_specific_folder_from_record(global_path, record_id, folder_path, Path::new(dest_str), global_password)?;
                        },
                        ("all-folder-versions", Some(sub_matches)) => {
                            let folder_path = sub_matches.value_of("folder").unwrap();
                            let dest_root_str = sub_matches.value_of("destination-root").unwrap();
                            evu::arq7_handler::restore_all_folder_versions(global_path, folder_path, Path::new(dest_root_str), global_password)?;
                        },
                        _ => println!("Invalid 'restore' subcommand for Arq 7. Use --help for details."),
                    }
                }
            }
        }
        ("list-files", Some(cmd)) => {
            match version {
                ArqVersion::Arq7 => {
                    let record_id = cmd.value_of("record");
                    let folder_path = cmd.value_of("folder");
                    evu::arq7_handler::list_files(global_path, global_password, record_id, folder_path)?;
                },
                ArqVersion::Arq5 => {
                    println!("'list-files' is not supported for Arq 5 backups.");
                }
            }
        }
        _ => {
            println!("No command specified or unknown command. Use --help for available commands.");
        }
    }
    Ok(())
}
