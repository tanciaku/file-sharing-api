use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Duration;
use http_body_util::BodyExt;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use crate::{AppState, auth::Claims, create_app};

const TEST_JWT_SECRET: &str = "test-secret";

pub async fn test_pool() -> PgPool {
    dotenvy::dotenv().ok();

    let db_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    sqlx::query!("TRUNCATE TABLE files, users RESTART IDENTITY CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    pool
}

fn make_app(pool: PgPool) -> axum::Router {
    create_app(AppState {
        pool,
        jwt_secret: TEST_JWT_SECRET.to_string(),
    })
}

fn make_jwt(user_id: i64, username: &str) -> String {
    let exp = chrono::Utc::now()
        .checked_add_signed(Duration::days(1))
        .unwrap()
        .timestamp() as usize;
    let claims = Claims {
        sub: username.to_string(),
        user_id,
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

async fn create_test_user(pool: &PgPool, username: &str, password: &str) -> i64 {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
        username,
        hash,
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .id
}

fn multipart_body(boundary: &str, filename: &str, content: &str) -> String {
    format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n{c}\r\n--{b}--\r\n",
        b = boundary,
        f = filename,
        c = content,
    )
}

// --- Tests ---

#[tokio::test]
async fn test_login_success() {
    let pool = test_pool().await;
    create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);

    let body = json!({ "username": "alice", "password": "password123" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["token"].as_str().is_some(),
        "expected a token in response"
    );
}

#[tokio::test]
async fn test_login_bad_credentials() {
    let pool = test_pool().await;
    create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);

    let body = json!({ "username": "alice", "password": "wrongpassword" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_upload_and_download() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);

    let token = make_jwt(alice_id, "alice");
    let boundary = "TestBoundary1234";
    let file_content = "hello from the test file";

    let upload_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(multipart_body(
                    boundary,
                    "test.txt",
                    file_content,
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(upload_response.status(), StatusCode::OK);

    let bytes = upload_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let file_id = std::str::from_utf8(&bytes)
        .unwrap()
        .strip_prefix("File ID: ")
        .unwrap()
        .trim()
        .to_string();

    let download_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/files/{}", file_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(download_response.status(), StatusCode::OK);

    let downloaded = download_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(downloaded.as_ref(), file_content.as_bytes());
}

#[tokio::test]
async fn test_delete_owner_vs_non_owner() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let bob_id = create_test_user(&pool, "bob", "password456").await;
    let app = make_app(pool);

    let alice_token = make_jwt(alice_id, "alice");
    let bob_token = make_jwt(bob_id, "bob");
    let boundary = "TestBoundary1234";

    // Alice uploads a file
    let upload_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header(header::AUTHORIZATION, format!("Bearer {}", alice_token))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(multipart_body(boundary, "alice.txt", "hello")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(upload_response.status(), StatusCode::OK);
    let bytes = upload_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let file_id = std::str::from_utf8(&bytes)
        .unwrap()
        .strip_prefix("File ID: ")
        .unwrap()
        .trim()
        .to_string();

    // Bob tries to delete Alice's file → 403
    let forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/files/{}", file_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    // Alice deletes her own file → 204
    let deleted = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/files/{}", file_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
}
