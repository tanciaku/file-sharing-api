use axum::{
    Router,
    extract::{FromRef, Multipart, Path, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::{auth::AuthUser, error::AppError};

mod auth;
mod error;
#[cfg(test)]
mod tests;

const UPLOAD_DIR: &str = "./uploads";

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

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    tokio::fs::create_dir_all(UPLOAD_DIR).await.unwrap();

    let state = AppState { pool, jwt_secret };

    let app = create_app(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on port 3000");
    axum::serve(listener, app).await.unwrap();
}

pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/upload", post(upload_file))
        .route("/files/{id}", get(download_file).delete(delete_file))
        .route("/auth/login", post(auth::login))
        .with_state(state)
}

async fn upload_file(
    State(pool): State<PgPool>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<String, AppError> {
    let user_id = auth.0.user_id;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest)?
    {
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            continue;
        }

        let file_name = field.file_name().unwrap_or("unknown").to_string();

        let data = field.bytes().await.map_err(|_| AppError::BadRequest)?;
        let size = data.len() as i64;
        let id = Uuid::new_v4();
        let save_path = format!("{}/{}", UPLOAD_DIR, id);

        tokio::fs::write(&save_path, &data)
            .await
            .map_err(|_| AppError::InternalError)?;

        sqlx::query!(
            "INSERT INTO files (id, original_name, size_bytes, user_id) VALUES ($1, $2, $3, $4)",
            id,
            file_name,
            size,
            user_id,
        )
        .execute(&pool)
        .await?;

        println!("Saved '{}' as '{}'", file_name, id);

        return Ok(format!("File ID: {}", id));
    }

    Err(AppError::BadRequest)
}

async fn download_file(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let record = sqlx::query!("SELECT original_name FROM files WHERE id = $1", id)
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| AppError::NotFound(id.to_string()))?;

    let file_path = format!("{}/{}", UPLOAD_DIR, id);
    let data = tokio::fs::read(&file_path)
        .await
        .map_err(|_| AppError::NotFound(id.to_string()))?;

    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", record.original_name),
        ),
    ];

    Ok((headers, data))
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
