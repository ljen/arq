use clap;

pub fn parse_flags<'a>() -> clap::ArgMatches<'a> {
    clap::App::new("evu")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about("Command line interface to ARQ (Supports Arq 5 and Arq 7)")
        .arg(
            clap::Arg::from_usage("-p --path [path] 'Path to the Arq backup data (computer UUID folder for Arq5, backup set root for Arq7)'")
                .global(true)
        )
        .arg( // Added global password argument
            clap::Arg::from_usage("--password [password] 'Password for encrypted Arq backups (optional)'")
                .global(true)
        )
        .subcommand(
            clap::SubCommand::with_name("show")
                .about("Display Arq 5 resources")
                .subcommand(clap::SubCommand::with_name("computers").about("Show computers (Arq 5)"))
                .subcommand(
                    clap::SubCommand::with_name("folders")
                        .about("Show folders for a computer (Arq 5)")
                        .args_from_usage("-c --computer [computer] 'Computer UUID (Arq 5)'"),
                )
                .subcommand(
                    clap::SubCommand::with_name("tree")
                        .about("Show tree for a folder (Arq 5)")
                        .args_from_usage(
                            "-c --computer [computer] 'Computer UUID (Arq 5)'
                             -f --folder [folder]     'Folder UUID (Arq 5)'",
                        ),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("restore")
                .about("Restore file from Arq 5 backup")
                .args_from_usage(
                    "-c --computer [computer]   'Computer UUID (Arq 5)'
                     -f --folder [folder]       'Folder UUID (Arq 5)'
                     <FILEPATH>                 'Absolute path to restore (Arq 5)'",
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("arq7")
                .about("Arq 7 backup operations")
                // Removed subcommand-specific --path; will rely on global --path
                // Removed subcommand-specific --password; will rely on global --password
                .subcommand(
                    clap::SubCommand::with_name("show-records")
                        .about("List all backup records in an Arq 7 backup set"),
                )
                .subcommand(
                    clap::SubCommand::with_name("show-file-versions")
                        .about("List all versions/records for a given file in an Arq 7 backup set")
                        .arg(clap::Arg::from_usage("--file <file_path_in_backup> 'Path of the file within the backup'").required(true)),
                )
                .subcommand(
                    clap::SubCommand::with_name("show-folder-versions")
                        .about("List all versions/records for a given folder in an Arq 7 backup set")
                        .arg(clap::Arg::from_usage("--folder <folder_path_in_backup> 'Path of the folder within the backup'").required(true)),
                )
                .subcommand(
                    clap::SubCommand::with_name("restore-record")
                        .about("Restore a full backup record from an Arq 7 backup set")
                        .arg(clap::Arg::from_usage("--record <record_identifier> 'Timestamp or partial timestamp of the record to restore'").required(true))
                        .arg(clap::Arg::from_usage("--destination <output_folder> 'Folder where the backup record will be restored'").required(true)),
                )
                .subcommand(
                    clap::SubCommand::with_name("restore-file")
                        .about("Restore a specific file from a specific backup record in an Arq 7 backup set")
                        .arg(clap::Arg::from_usage("--record <record_identifier> 'Timestamp or partial timestamp of the record'").required(true))
                        .arg(clap::Arg::from_usage("--file <file_path_in_backup> 'Path of the file within the backup to restore'").required(true))
                        .arg(clap::Arg::from_usage("--destination <output_path_or_folder> 'Full path for the restored file or folder to restore into'").required(true)),
                )
                .subcommand(
                    clap::SubCommand::with_name("restore-folder")
                        .about("Restore a specific folder from a specific backup record in an Arq 7 backup set")
                        .arg(clap::Arg::from_usage("--record <record_identifier> 'Timestamp or partial timestamp of the record'").required(true))
                        .arg(clap::Arg::from_usage("--folder <folder_path_in_backup> 'Path of the folder within the backup to restore'").required(true))
                        .arg(clap::Arg::from_usage("--destination <output_folder> 'Folder where the backup folder content will be restored'").required(true)),
                )
                .subcommand(
                    clap::SubCommand::with_name("restore-all-folder-versions")
                        .about("Restore all versions of a specific folder from an Arq 7 backup set")
                        .arg(clap::Arg::from_usage("--folder <folder_path_in_backup> 'Path of the folder within the backup to restore'").required(true))
                        .arg(clap::Arg::from_usage("--destination-root <output_root_folder> 'Root folder where versions will be restored into subdirectories named by record timestamp'").required(true)),
                )
                .subcommand(
                    clap::SubCommand::with_name("list-files")
                        .about("List files and folders in an Arq 7 backup record")
                        .arg(clap::Arg::from_usage("--record [record_identifier] 'Timestamp or partial timestamp of the record to list files from'"))
                        .arg(clap::Arg::from_usage("--folder [folder_path_in_backup] 'Path of the folder within the backup to list'")),
                )
        )
        .get_matches()
}
