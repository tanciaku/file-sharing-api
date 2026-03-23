use axum::{
    Router,
    routing::{get, post},
    extract::Multipart,
    http::StatusCode,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
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

        println!("Received file: '{}' ({} bytes)", file_name, data.len());

        return Ok(format!("Uploaded: {} ({} bytes)", file_name, data.len()));
    }

    Err(StatusCode::BAD_REQUEST)
}

async fn download_file() -> &'static str {
    "Download endpoint - TODO"
}