use axum::body::Body;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRef, Multipart, Path, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::{auth::AuthUser, error::AppError};

mod auth;
mod error;
#[cfg(test)]
mod tests;

const UPLOAD_DIR: &str = "./uploads";
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

const ALLOWED_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "pdf", "txt"];

const ALLOWED_MIME_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
    "text/plain",
];

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_secret: String,
}

impl FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

#[derive(Serialize)]
pub struct FileMetadata {
    pub id: Uuid,
    pub original_name: String,
    pub size_bytes: i64,
    pub uploaded_at: DateTime<Utc>,
    pub download_count: i64,
}

#[derive(Deserialize)]
pub struct ListFilesParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Serialize)]
pub struct PaginatedFiles {
    pub files: Vec<FileMetadata>,
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
}

#[derive(Serialize)]
pub struct ShareTokenResponse {
    pub token: Uuid,
    pub expires_at: DateTime<Utc>,
    pub download_url: String,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    tokio::fs::create_dir_all(UPLOAD_DIR).await.unwrap();

    let state = AppState { pool, jwt_secret };

    let app = create_app(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!(port = port, "Server started");

    axum::serve(listener, app).await.unwrap();
}

pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/upload", post(upload_file))
        .route("/files", get(list_files))
        .route("/files/{id}", get(download_file).delete(delete_file))
        .route("/files/{id}/meta", get(get_file_meta))
        .route("/files/{id}/share", post(create_share_token))
        .route("/files/shared/{token}", get(download_shared_file))
        .route("/auth/login", post(auth::login))
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn upload_file(
    State(pool): State<PgPool>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<String, AppError> {
    let user_id = auth.0.user_id;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest)?
    {
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            continue;
        }

        let file_name = field.file_name().unwrap_or("unknown").to_string();

        let ext = std::path::Path::new(&file_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            return Err(AppError::UnsupportedMediaType);
        }

        let content_type = field.content_type().unwrap_or("").to_string();
        if !ALLOWED_MIME_TYPES.contains(&content_type.as_str()) {
            return Err(AppError::UnsupportedMediaType);
        }

        let id = Uuid::new_v4();
        let save_path = format!("{}/{}", UPLOAD_DIR, id);

        let mut file = tokio::fs::File::create(&save_path)
            .await
            .map_err(|_| AppError::InternalError)?;

        let mut total_size: usize = 0;

        while let Some(chunk) = field.chunk().await.map_err(|_| AppError::BadRequest)? {
            total_size += chunk.len();

            if total_size > MAX_FILE_SIZE {
                let _ = tokio::fs::remove_file(&save_path).await;
                return Err(AppError::FileTooLarge);
            }

            if let Err(_) = file.write_all(&chunk).await {
                let _ = tokio::fs::remove_file(&save_path).await;
                return Err(AppError::InternalError);
            }
        }

        let size = total_size as i64;

        sqlx::query!(
            "INSERT INTO files (id, original_name, size_bytes, user_id) VALUES ($1, $2, $3, $4)",
            id,
            file_name,
            size,
            user_id,
        )
        .execute(&pool)
        .await?;

        info!(file_name = %file_name, file_id = %id, user_id = user_id, "File uploaded");

        return Ok(format!("File ID: {}", id));
    }

    Err(AppError::BadRequest)
}

async fn download_file(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let record = sqlx::query!(
        "UPDATE files SET download_count = download_count + 1 WHERE id = $1 RETURNING original_name",
        id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| AppError::NotFound(id.to_string()))?;

    let file_path = format!("{}/{}", UPLOAD_DIR, id);

    let file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|_| AppError::NotFound(id.to_string()))?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", record.original_name),
        ),
    ];

    Ok((headers, body))
}

async fn delete_file(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    auth: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user_id = auth.0.user_id;

    let mut tx = pool.begin().await?;

    let record = sqlx::query!("SELECT user_id FROM files WHERE id = $1", id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound(id.to_string()))?;

    if record.user_id != user_id {
        return Err(AppError::Forbidden);
    }

    sqlx::query!("DELETE FROM files WHERE id = $1", id)
        .execute(&mut *tx)
        .await?;

    let file_path = format!("{}/{}", UPLOAD_DIR, id);
    tokio::fs::remove_file(&file_path)
        .await
        .map_err(|_| AppError::InternalError)?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_files(
    State(pool): State<PgPool>,
    auth: AuthUser,
    Query(params): Query<ListFilesParams>,
) -> Result<Json<PaginatedFiles>, AppError> {
    let user_id = auth.0.user_id;

    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let offset = ((page - 1) * per_page) as i64;
    let limit = per_page as i64;

    let total = sqlx::query!("SELECT COUNT(*) FROM files WHERE user_id = $1", user_id)
        .fetch_one(&pool)
        .await?
        .count
        .unwrap_or(0);

    let rows = sqlx::query!(
        "SELECT id, original_name, size_bytes, uploaded_at, download_count
         FROM files
         WHERE user_id = $1
         ORDER BY uploaded_at DESC
         LIMIT $2 OFFSET $3",
        user_id,
        limit,
        offset
    )
    .fetch_all(&pool)
    .await?;

    let files = rows
        .into_iter()
        .map(|r| FileMetadata {
            id: r.id,
            original_name: r.original_name,
            size_bytes: r.size_bytes,
            uploaded_at: r.uploaded_at,
            download_count: r.download_count,
        })
        .collect();

    Ok(Json(PaginatedFiles {
        files,
        page,
        per_page,
        total,
    }))
}

async fn create_share_token(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    auth: AuthUser,
) -> Result<Json<ShareTokenResponse>, AppError> {
    let user_id = auth.0.user_id;

    let record = sqlx::query!("SELECT user_id FROM files WHERE id = $1", id)
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| AppError::NotFound(id.to_string()))?;

    if record.user_id != user_id {
        return Err(AppError::Forbidden);
    }

    let token = Uuid::new_v4();
    let expires_at = Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .unwrap();

    sqlx::query!(
        "INSERT INTO share_tokens (token, file_id, expires_at) VALUES ($1, $2, $3)",
        token,
        id,
        expires_at,
    )
    .execute(&pool)
    .await?;

    Ok(Json(ShareTokenResponse {
        token,
        expires_at,
        download_url: format!("/files/shared/{}", token),
    }))
}

async fn download_shared_file(
    State(pool): State<PgPool>,
    Path(token): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let record = sqlx::query!(
        "SELECT f.id AS file_id, f.original_name, st.expires_at
         FROM share_tokens st
         JOIN files f ON f.id = st.file_id
         WHERE st.token = $1",
        token
    )
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| AppError::NotFound(token.to_string()))?;

    if record.expires_at < Utc::now() {
        return Err(AppError::Gone);
    }

    sqlx::query!(
        "UPDATE files SET download_count = download_count + 1 WHERE id = $1",
        record.file_id
    )
    .execute(&pool)
    .await?;

    let file_path = format!("{}/{}", UPLOAD_DIR, record.file_id);

    let file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|_| AppError::InternalError)?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", record.original_name),
        ),
    ];

    Ok((headers, body))
}

async fn get_file_meta(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    auth: AuthUser,
) -> Result<Json<FileMetadata>, AppError> {
    let user_id = auth.0.user_id;

    let record = sqlx::query!(
        "SELECT id, original_name, size_bytes, uploaded_at, download_count
         FROM files
         WHERE id = $1 AND user_id = $2",
        id,
        user_id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| AppError::NotFound(id.to_string()))?;

    Ok(Json(FileMetadata {
        id: record.id,
        original_name: record.original_name,
        size_bytes: record.size_bytes,
        uploaded_at: record.uploaded_at,
        download_count: record.download_count,
    }))
}
