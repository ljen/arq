# evu

Implementation of ARQ data format and command line tool to restore backups

Note: there is no caching in this early state of the tool therefore all commands are much
more inneficient than they should be.

## Build

```rust
cargo build --release
```

## Usage

`evu` works with local paths for Arq backup data.

*   For **Arq 5**: The `--path` option should point to the computer's UUID folder within your Arq backup destination (e.g., `s3_backup_root/YOUR_COMPUTER_UUID/`).
*   For **Arq 7**: The `--path` option (either global or for the `arq7` subcommand) should point to the root of the Arq 7 backup set (the directory containing `backupconfig.json`, `backupfolders.json`, etc.).

An optional global `--password` flag can be used for encrypted backups.

### General Help

```bash
evu --help
```

### Arq 5 Commands

Arq 5 commands are for interacting with older Arq backup formats.

**Show Commands (Arq 5):**

*   `evu --path <arq5_computer_uuid_path> show computers`: List computers.
*   `evu --path <arq5_computer_uuid_path> show folders --computer <computer_uuid>`: List backup folders for a specific computer.
*   `evu --path <arq5_computer_uuid_path> show tree --computer <computer_uuid> --folder <folder_uuid>`: Display the file tree for a specific backup folder.

**Restore Command (Arq 5):**

*   `evu --path <arq5_computer_uuid_path> restore --computer <computer_uuid> --folder <folder_uuid> <absolute_filepath_to_restore>`: Restore a file from an Arq 5 backup.

### Arq 7 Commands

The `arq7` subcommand provides operations specific to Arq 7 backups.

```bash
evu arq7 --help
```

**Common Options for `arq7` subcommands:**

*   `--path <path_to_arq7_backup_set>`: Specifies the root directory of the Arq 7 backup set. This is required for all `arq7` commands.
*   `--password <password>`: Password for encrypted Arq 7 backups. Can also be provided globally.

**List Backup Records (Arq 7):**

```bash
evu arq7 --path <path_to_arq7_backup_set> [--password <password>] show-records
```
Lists all backup records (snapshots) found in the Arq 7 backup set, grouped by original backup folder.

**List File Versions (Arq 7):**

```bash
evu arq7 --path <path_to_arq7_backup_set> [--password <password>] show-file-versions --file <path_of_file_in_backup>
```
Lists all available versions of a specific file across all backup records where it appears. The `<path_of_file_in_backup>` should be the full path as it was backed up (e.g., `/Users/me/Documents/report.docx` or relative if the backup source was a subfolder like `MyFolder/report.docx`).

**List Folder Versions (Arq 7):**

```bash
evu arq7 --path <path_to_arq7_backup_set> [--password <password>] show-folder-versions --folder <path_of_folder_in_backup>
```
Lists all available versions of a specific folder across all backup records.

**Restore Full Backup Record (Arq 7):**

```bash
evu arq7 --path <path_to_arq7_backup_set> [--password <password>] restore-record --record <record_identifier> --destination <output_folder>
```
Restores the entire content of a specific backup record. The `<record_identifier>` is typically the timestamp (or a unique prefix of it) of the backup record, obtainable from `show-records`. The restored files will be placed in a subdirectory named `record_<timestamp>` inside the `<output_folder>`.

**Restore Specific File from Record (Arq 7):**

```bash
evu arq7 --path <path_to_arq7_backup_set> [--password <password>] restore-file --record <record_identifier> --file <path_of_file_in_backup> --destination <output_path_or_folder>
```
Restores a single file from a specific backup record. If `<destination>` is a directory, the file is restored into it with its original name. If `<destination>` is a full path, the file is restored to that path.

**Restore Specific Folder from Record (Arq 7):**

```bash
evu arq7 --path <path_to_arq7_backup_set> [--password <password>] restore-folder --record <record_identifier> --folder <path_of_folder_in_backup> --destination <output_folder>
```
Restores a specific folder and its contents from a particular backup record. The contents of the backed-up folder will be placed into a subdirectory named after the original folder's name, inside the specified `<output_folder>`. For example, if restoring `/Users/me/Photos` to `/tmp/restored`, the files will end up in `/tmp/restored/Photos/...`.

**Restore All Versions of a Folder (Arq 7):**

```bash
evu arq7 --path <path_to_arq7_backup_set> [--password <password>] restore-all-folder-versions --folder <path_of_folder_in_backup> --destination-root <output_root_folder>
```
Restores all found versions of a specific folder. Each version (from each backup record where the folder exists) will be restored into a subdirectory named `version_<timestamp>` under the `<output_root_folder>`. Inside each `version_<timestamp>` directory, the folder's contents will be placed in a subdirectory named after the original folder.

### Example Workflow (Arq 7)

1.  **List records to find a snapshot:**
    ```bash
    evu arq7 --path /mnt/backups/my_arq7_backup --password "mysecret" show-records
    ```
    *(Note a record timestamp, e.g., `1736712823000`)*

2.  **List versions of a specific file:**
    ```bash
    evu arq7 --path /mnt/backups/my_arq7_backup --password "mysecret" show-file-versions --file "/Users/me/Documents/important.docx"
    ```

3.  **Restore a specific file from that record:**
    ```bash
    evu arq7 --path /mnt/backups/my_arq7_backup --password "mysecret" restore-file --record 1736712823000 --file "/Users/me/Documents/important.docx" --destination /tmp/restored_files/
    ```

4.  **Restore a whole folder from that record:**
    ```bash
    evu arq7 --path /mnt/backups/my_arq7_backup --password "mysecret" restore-folder --record 1736712823000 --folder "/Users/me/Pictures" --destination /tmp/restored_pictures/
    ```
    *(This would create `/tmp/restored_pictures/Pictures/...`)*
