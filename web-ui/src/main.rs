use axum::{
    extract::{Form, Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router, Json,
};
use askama::Template;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use arq::arq7::{BackupSet, EncryptedKeySet};
use std::path::PathBuf;
use arq::node::Node;

#[derive(Clone)]
struct AppState {
    backup_set: Arc<Mutex<Option<Arc<BackupSet>>>>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "browser.html")]
struct BrowserTemplate {
    folders: Vec<FolderView>,
}

struct FolderView {
    name: String,
    records: Vec<RecordView>,
}

struct RecordView {
    id: String,
    date: String,
}

#[derive(Deserialize)]
struct LoadForm {
    path: String,
    password: Option<String>,
}

#[derive(Deserialize)]
struct TreeQuery {
    path: Option<String>,
}

#[derive(Serialize)]
struct TreeResponse {
    items: Vec<TreeItem>,
}

#[derive(Serialize)]
struct TreeItem {
    name: String,
    is_dir: bool,
    size: u64,
}

#[derive(Serialize)]
struct TreeDirsResponse {
    dirs: Vec<TreeDirItem>,
}

#[derive(Serialize)]
struct TreeDirItem {
    name: String,
    has_children: bool,
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let bs = state.backup_set.lock().await;
    if bs.is_some() {
        return Redirect::to("/browse").into_response();
    }
    IndexTemplate { error: None }.into_response()
}

async fn load_backup(State(state): State<AppState>, Form(form): Form<LoadForm>) -> impl IntoResponse {
    let path = PathBuf::from(form.path);
    let pwd = form.password.filter(|s| !s.is_empty());

    // Use spawn_blocking for long running sync code
    let bs_result = tokio::task::spawn_blocking(move || {
        BackupSet::from_directory_with_password(&path, pwd.as_deref())
    }).await.unwrap_or_else(|e| Err(arq::error::Error::InvalidFormat(format!("Task panic: {:?}", e))));

    match bs_result {
        Ok(bs) => {
            let mut state_bs = state.backup_set.lock().await;
            *state_bs = Some(Arc::new(bs));
            Redirect::to("/browse").into_response()
        }
        Err(e) => {
            IndexTemplate {
                error: Some(format!("Failed to load backup: {:?}", e)),
            }.into_response()
        }
    }
}

async fn browse(State(state): State<AppState>) -> impl IntoResponse {
    let bs_lock = state.backup_set.lock().await;
    let bs = match bs_lock.as_ref() {
        Some(b) => b,
        None => return Redirect::to("/").into_response(),
    };

    let mut folders = Vec::new();
    for (folder_uuid, records) in &bs.backup_records {
        let folder_name = bs.backup_folder_configs.get(folder_uuid)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| "Unknown Folder".to_string());

        let mut record_views = Vec::new();
        for record in records {
            if let arq::arq7::GenericBackupRecord::Arq7(r) = record {
                let date = format_timestamp_rfc3339(r.node.creation_time_sec as f64);
                // Creating a somewhat unique ID for the UI
                let id = format!("{}_{}", folder_uuid, r.node.creation_time_sec);
                record_views.push(RecordView { id, date });
            }
        }

        // Sort by date descending
        record_views.sort_by(|a, b| b.date.cmp(&a.date));

        folders.push(FolderView {
            name: folder_name,
            records: record_views,
        });
    }

    BrowserTemplate { folders }.into_response()
}

fn get_arq7_record<'a>(bs: &'a BackupSet, record_id: &str) -> Option<&'a arq::arq7::Arq7BackupRecord> {
    let parts: Vec<&str> = record_id.split('_').collect();
    if parts.len() != 2 { return None; }
    let folder_uuid = parts[0];
    let time_sec_str = parts[1];
    let time_sec: i64 = time_sec_str.parse().ok()?;

    if let Some(records) = bs.backup_records.get(folder_uuid) {
        for gen_rec in records {
            if let arq::arq7::GenericBackupRecord::Arq7(r) = gen_rec {
                if r.node.creation_time_sec == time_sec {
                    return Some(r);
                }
            }
        }
    }
    None
}

async fn get_tree(
    State(state): State<AppState>,
    AxumPath(record_id): AxumPath<String>,
    Query(query): Query<TreeQuery>,
) -> impl IntoResponse {
    let bs_lock = state.backup_set.lock().await;
    let bs = match bs_lock.as_ref() {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, "Not loaded").into_response(),
    };

    let record = match get_arq7_record(bs, &record_id) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "Record not found").into_response(),
    };

    // Resolve the path
    let req_path = query.path.unwrap_or_default();

    let bs_clone = Arc::clone(bs);
    let root_node = record.node.clone();

    let result = tokio::task::spawn_blocking(move || {
        let keyset = bs_clone.encryption_keyset();
        match resolve_node(&bs_clone, &root_node, &req_path, keyset) {
            Ok(node) => {
                if !node.is_tree {
                    return Err(StatusCode::BAD_REQUEST);
                }
                match list_node_children(&bs_clone, &node, keyset) {
                    Ok(children) => Ok(children),
                    Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                }
            }
            Err(_) => Err(StatusCode::NOT_FOUND),
        }
    }).await.unwrap_or(Err(StatusCode::INTERNAL_SERVER_ERROR));

    match result {
        Ok(children) => Json(TreeResponse { items: children }).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn get_tree_dirs(
    State(state): State<AppState>,
    AxumPath(record_id): AxumPath<String>,
    Query(query): Query<TreeQuery>,
) -> impl IntoResponse {
    let bs_lock = state.backup_set.lock().await;
    let bs = match bs_lock.as_ref() {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, "Not loaded").into_response(),
    };

    let record = match get_arq7_record(bs, &record_id) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "Record not found").into_response(),
    };

    let req_path = query.path.unwrap_or_default();
    let bs_clone = bs.clone();
    let root_node = record.node.clone();

    let result = tokio::task::spawn_blocking(move || {
        let keyset = bs_clone.encryption_keyset();
        match resolve_node(&bs_clone, &root_node, &req_path, keyset) {
            Ok(node) => {
                if !node.is_tree {
                    return Err(StatusCode::BAD_REQUEST);
                }
                match list_node_subdirs(&bs_clone, &node, keyset) {
                    Ok(dirs) => Ok(dirs),
                    Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                }
            }
            Err(_) => Err(StatusCode::NOT_FOUND),
        }
    }).await.unwrap_or(Err(StatusCode::INTERNAL_SERVER_ERROR));

    match result {
        Ok(dirs) => Json(TreeDirsResponse { dirs }).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn download_file(
    State(state): State<AppState>,
    AxumPath(record_id): AxumPath<String>,
    Query(query): Query<TreeQuery>,
) -> impl IntoResponse {
    let bs_lock = state.backup_set.lock().await;
    let bs = match bs_lock.as_ref() {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, "Not loaded").into_response(),
    };

    let record = match get_arq7_record(bs, &record_id) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "Record not found").into_response(),
    };

    // Resolve the path
    let req_path = match query.path {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => return (StatusCode::BAD_REQUEST, "Path is required").into_response(),
    };

    let bs_clone = Arc::clone(bs);
    let root_node = record.node.clone();

    let result = tokio::task::spawn_blocking(move || {
        let keyset = bs_clone.encryption_keyset();
        match resolve_node(&bs_clone, &root_node, &req_path, keyset) {
            Ok(node) => {
                if node.is_tree {
                    return Err(StatusCode::BAD_REQUEST);
                }
                match node.reconstruct_file_data_with_encryption(&bs_clone.root_path, keyset) {
                    Ok(data) => Ok(data),
                    Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                }
            }
            Err(_) => Err(StatusCode::NOT_FOUND),
        }
    }).await.unwrap_or(Err(StatusCode::INTERNAL_SERVER_ERROR));

    match result {
        Ok(data) => {
            let req_path = query.path.unwrap();
            let parts: Vec<&str> = req_path.split('/').collect();
            let filename = parts.last().unwrap_or(&"file");
            let headers = axum::response::AppendHeaders([
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", filename),
                ),
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/octet-stream".to_string(),
                ),
            ]);
            (headers, data).into_response()
        },
        Err(status) => status.into_response(),
    }
}

fn resolve_node(
    bs: &BackupSet,
    root: &Node,
    path: &str,
    keyset: Option<&EncryptedKeySet>,
) -> anyhow::Result<Node> {
    if path.is_empty() {
        return Ok(root.clone());
    }

    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current_node = root.clone();

    for part in parts {
        if !current_node.is_tree {
            return Err(anyhow::anyhow!("Not a directory"));
        }

        let tree = current_node.load_tree_with_encryption(&bs.root_path, keyset)
            .map_err(|e| anyhow::anyhow!("Failed to read tree: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("Tree data missing"))?;

        let mut found = false;
        for (name, node) in tree.nodes {
            if name == part {
                current_node = node;
                found = true;
                break;
            }
        }
        if !found {
            return Err(anyhow::anyhow!("Not found"));
        }
    }

    Ok(current_node)
}

fn list_node_children(
    bs: &BackupSet,
    node: &Node,
    keyset: Option<&EncryptedKeySet>,
) -> anyhow::Result<Vec<TreeItem>> {
    let mut items = Vec::new();
    if !node.is_tree {
        return Ok(items);
    }

    let tree = node.load_tree_with_encryption(&bs.root_path, keyset)
        .map_err(|e| anyhow::anyhow!("Failed to read tree: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Tree data missing"))?;

    for (name, child_node) in tree.nodes {
        items.push(TreeItem {
            name,
            is_dir: child_node.is_tree,
            size: child_node.item_size,
        });
    }

    // sort: directories first, then alphabetically
    items.sort_by(|a, b| {
        if a.is_dir == b.is_dir {
            a.name.cmp(&b.name)
        } else if a.is_dir {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });

    Ok(items)
}

fn list_node_subdirs(
    bs: &BackupSet,
    node: &Node,
    keyset: Option<&EncryptedKeySet>,
) -> anyhow::Result<Vec<TreeDirItem>> {
    let mut dirs = Vec::new();
    if !node.is_tree {
        return Ok(dirs);
    }

    let tree = node.load_tree_with_encryption(&bs.root_path, keyset)
        .map_err(|e| anyhow::anyhow!("Failed to read tree: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("Tree data missing"))?;

    for (name, child_node) in &tree.nodes {
        if child_node.is_tree {
            // Check if this directory itself has subdirectories
            let has_children = if let Ok(Some(child_tree)) = child_node.load_tree_with_encryption(&bs.root_path, keyset) {
                child_tree.nodes.iter().any(|(_, n)| n.is_tree)
            } else {
                false // Assume no children if we can't load
            };
            dirs.push(TreeDirItem {
                name: name.clone(),
                has_children,
            });
        }
    }

    dirs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(dirs)
}

// Simple helper from evu
fn format_timestamp_rfc3339(ts_f64: f64) -> String {
    let secs = ts_f64 as i64;
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts_f64.to_string())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let state = AppState {
        backup_set: Arc::new(Mutex::new(None)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/load", post(load_backup))
        .route("/browse", get(browse))
        .route("/api/record/:record_id/tree", get(get_tree))
        .route("/api/record/:record_id/tree_dirs", get(get_tree_dirs))
        .route("/api/record/:record_id/download", get(download_file))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;

    Ok(())
}
