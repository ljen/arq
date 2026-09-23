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
*   For **Arq 7**: The `--path` option should point to the root of the Arq 7 backup set (the directory containing `backupconfig.json`, `backupfolders.json`, etc.).

For encrypted backups, set `ARQ_PASSWORD` or enter the password at the interactive prompt.

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

Arq 7 is selected automatically when `--path` points at a backup set containing
`backupconfig.json`. There is no separate `arq7` top-level subcommand.

**Common Options for Arq 7 commands:**

*   `--path <path_to_arq7_backup_set>`: Specifies the root directory of the Arq 7 backup set. This is required for all Arq 7 commands.
*   `ARQ_PASSWORD`: Environment variable for encrypted backup passwords; otherwise EVU prompts.

**List Backup Records (Arq 7):**

```bash
evu --path <path_to_arq7_backup_set> show records
```
Lists all backup records (snapshots) found in the Arq 7 backup set, grouped by original backup folder.

**List File Versions (Arq 7):**

```bash
evu --path <path_to_arq7_backup_set> show file-versions --file <path_of_file_in_backup>
```
Lists all available versions of a specific file across all backup records where it appears. The `<path_of_file_in_backup>` should be the full path as it was backed up (e.g., `/Users/me/Documents/report.docx` or relative if the backup source was a subfolder like `MyFolder/report.docx`).

**List Folder Versions (Arq 7):**

```bash
evu --path <path_to_arq7_backup_set> show folder-versions --folder <path_of_folder_in_backup>
```
Queries an exact folder path across all native Arq 7 records in the backup set.
Use an absolute original path, or a relative path such as `Pictures/holidays`
to query that location relative to every backup root. `/` selects each root.
Absolute paths use each record's historical source path; current folder configuration
is only a fallback when the record has no source path. Matching is case-sensitive
and respects path components (`/Photos` does not match `/Photos-old`).
The output includes the source folder UUID, timestamp, backup completeness,
backup error count, and planned output directory. Unchanged snapshots are included.

**Restore Full Backup Record (Arq 7):**

```bash
evu --path <path_to_arq7_backup_set> restore record --record <record_identifier> --destination <output_folder>
```
Restores the entire content of a specific backup record. The `<record_identifier>` is typically the timestamp (or a unique prefix of it) of the backup record, obtainable from `show records`. The restored files will be placed in a subdirectory named `record_<timestamp>` inside the `<output_folder>`.

**Restore Specific File from Record (Arq 7):**

```bash
evu --path <path_to_arq7_backup_set> restore file --record <record_identifier> --file <path_of_file_in_backup> --destination <output_path_or_folder>
```
Restores a single file from a specific backup record. If `<destination>` is a directory, the file is restored into it with its original name. If `<destination>` is a full path, the file is restored to that path.

**Restore Specific Folder from Record (Arq 7):**

```bash
evu --path <path_to_arq7_backup_set> restore folder --record <record_identifier> --folder <path_of_folder_in_backup> --destination <output_folder>
```
Restores a specific folder and its contents from a particular backup record. The contents of the backed-up folder will be placed into a subdirectory named after the original folder's name, inside the specified `<output_folder>`. For example, if restoring `/Users/me/Photos` to `/tmp/restored`, the files will end up in `/tmp/restored/Photos/...`.

**Restore All Versions of a Folder (Arq 7):**

```bash
evu --path <path_to_arq7_backup_set> restore all-folder-versions --folder <path_of_folder_in_backup> --destination-root <output_root_folder>
```
Restores every matching record using the same query as `show folder-versions`.
Each record gets a timestamp directory; repeated timestamps receive a record suffix
so versions cannot overwrite each other. Each directory contains the requested
folder and `restore.json` with source identity, backup health, restored byte/file
counts and status (`in_progress`, `complete`, or `failed`). `/` uses `root_content`.
If the requested folder is itself named `restore.json`, the manifest is named
`restore-manifest.json`.

Choose an output directory outside the backup set. Existing version directories
are rejected, including on reruns. A failed restore exits unsuccessfully and leaves
its output and manifest for inspection; use a fresh destination for another attempt.
Files are checked against their recorded size. Restoring currently extracts file
bytes and modification times, not a complete reproduction of filesystem metadata
such as ACLs, hard links, or symlinks.

Unreadable records or trees fail the operation instead of silently omitting versions.
Imported Arq 5 records inside an Arq 7 set are not yet supported by folder history;
EVU explicitly refuses an incomplete history result when they are present.

```bash
# Query all records first (read-only)
evu --path /mnt/backups/my_arq7_backup show folder-versions --folder "Pictures/holidays"

# Restore every matching snapshot into a separate directory
evu --path /mnt/backups/my_arq7_backup restore all-folder-versions \
  --folder "Pictures/holidays" --destination-root /tmp/holiday-history
```

### Example Workflow (Arq 7)

1.  **List records to find a snapshot:**
    ```bash
    evu --path /mnt/backups/my_arq7_backup show records
    ```
    *(Note a record timestamp, e.g., `1736712823`. `1736712823.0` and millisecond-form `1736712823000` are also accepted.)*

2.  **List versions of a specific file:**
    ```bash
    evu --path /mnt/backups/my_arq7_backup show file-versions --file "/Users/me/Documents/important.docx"
    ```

3.  **Restore a specific file from that record:**
    ```bash
    evu --path /mnt/backups/my_arq7_backup restore file --record 1736712823 --file "/Users/me/Documents/important.docx" --destination /tmp/restored_files/
    ```

4.  **Restore a whole folder from that record:**
    ```bash
    evu --path /mnt/backups/my_arq7_backup restore folder --record 1736712823 --folder "/Users/me/Pictures" --destination /tmp/restored_pictures/
    ```
    *(This would create `/tmp/restored_pictures/Pictures/...`)*
