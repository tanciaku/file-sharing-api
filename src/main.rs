use axum::{
    Router,
    routing::{get, post},
    extract::Multipart,
    http::StatusCode,
};
use tokio::net::TcpListener;
use uuid::Uuid;

const UPLOAD_DIR: &str = "./uploads";

#[tokio::main]
async fn main() {
    tokio::fs::create_dir_all(UPLOAD_DIR).await.unwrap();

    let app = Router::new()
        .route("/upload", post(upload_file))
        .route("/files/{id}", get(download_file));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on port 3000");
    axum::serve(listener, app).await.unwrap();
}

async fn upload_file(mut multipart: Multipart) -> Result<String, StatusCode> {
    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            continue;
        }

        let file_name = field.file_name()
            .unwrap_or("unknown")
            .to_string();

        let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;

        let id = Uuid::new_v4().to_string();

        let save_path = format!("{}/{}", UPLOAD_DIR, id);

        tokio::fs::write(&save_path, &data)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        println!("Saved '{}' as '{}'", file_name, id);

        return Ok(format!("File ID: {}", id));
    }

    Err(StatusCode::BAD_REQUEST)
}

async fn download_file() -> &'static str {
    "Download endpoint - TODO"
}
