use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

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

fn multipart_body(boundary: &str, filename: &str, content_type: &str, content: &str) -> String {
    format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{f}\"\r\nContent-Type: {ct}\r\n\r\n{c}\r\n--{b}--\r\n",
        b = boundary,
        f = filename,
        ct = content_type,
        c = content,
    )
}

async fn upload_file_for_user(app: axum::Router, token: &str, filename: &str) -> String {
    let boundary = "TestBoundary1234";
    let response = app
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
                    filename,
                    "text/plain",
                    "content",
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    std::str::from_utf8(&bytes)
        .unwrap()
        .strip_prefix("File ID: ")
        .unwrap()
        .trim()
        .to_string()
}

async fn create_share_token_for_file(app: axum::Router, token: &str, file_id: &str) -> Value {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/files/{}/share", file_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// --- Tests ---

#[tokio::test]
async fn test_upload_rejects_disallowed_extension() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);
    let token = make_jwt(alice_id, "alice");
    let boundary = "TestBoundary1234";

    let response = app
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
                    "malware.exe",
                    "text/plain",
                    "bad",
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_upload_rejects_disallowed_mime_type() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);
    let token = make_jwt(alice_id, "alice");
    let boundary = "TestBoundary1234";

    let response = app
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
                    "file.txt",
                    "application/octet-stream",
                    "bad",
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_upload_rejects_oversized_file() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);
    let token = make_jwt(alice_id, "alice");
    let boundary = "TestBoundary1234";

    let big_content = "a".repeat(11 * 1024 * 1024); // 11 MB
    let response = app
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
                    "big.txt",
                    "text/plain",
                    &big_content,
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

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
                    "text/plain",
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
async fn test_list_files_returns_own_files() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);
    let token = make_jwt(alice_id, "alice");

    upload_file_for_user(app.clone(), &token, "myfile.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/files")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["total"], 1);
    assert_eq!(json["files"].as_array().unwrap().len(), 1);
    assert_eq!(json["files"][0]["original_name"], "myfile.txt");
}

#[tokio::test]
async fn test_list_files_excludes_other_users_files() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let bob_id = create_test_user(&pool, "bob", "password456").await;
    let app = make_app(pool);
    let alice_token = make_jwt(alice_id, "alice");
    let bob_token = make_jwt(bob_id, "bob");

    upload_file_for_user(app.clone(), &alice_token, "alice.txt").await;
    upload_file_for_user(app.clone(), &bob_token, "bob.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/files")
                .header(header::AUTHORIZATION, format!("Bearer {}", alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["total"], 1);
    let files = json["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["original_name"], "alice.txt");
}

#[tokio::test]
async fn test_list_files_pagination() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);
    let token = make_jwt(alice_id, "alice");

    for i in 0..3 {
        upload_file_for_user(app.clone(), &token, &format!("file{}.txt", i)).await;
    }

    // Page 1: expect 2 results, total 3
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/files?page=1&per_page=2")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["total"], 3);
    assert_eq!(json["per_page"], 2);
    assert_eq!(json["files"].as_array().unwrap().len(), 2);

    // Page 2: expect 1 result
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/files?page=2&per_page=2")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["files"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_list_files_requires_auth() {
    let pool = test_pool().await;
    let app = make_app(pool);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/files")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
                .body(Body::from(multipart_body(
                    boundary,
                    "alice.txt",
                    "text/plain",
                    "hello",
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

#[tokio::test]
async fn test_create_share_token() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);
    let token = make_jwt(alice_id, "alice");

    let file_id = upload_file_for_user(app.clone(), &token, "share_me.txt").await;
    let json = create_share_token_for_file(app, &token, &file_id).await;

    assert!(json["token"].as_str().is_some(), "expected a token UUID");
    assert!(
        json["download_url"]
            .as_str()
            .unwrap()
            .starts_with("/files/shared/"),
        "expected download_url to point at the shared endpoint"
    );
}

#[tokio::test]
async fn test_create_share_token_forbidden() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let bob_id = create_test_user(&pool, "bob", "password456").await;
    let app = make_app(pool);
    let alice_token = make_jwt(alice_id, "alice");
    let bob_token = make_jwt(bob_id, "bob");

    let file_id = upload_file_for_user(app.clone(), &alice_token, "alice.txt").await;

    // Bob tries to create a share token for Alice's file → 403
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/files/{}/share", file_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_download_shared_file() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool);
    let token = make_jwt(alice_id, "alice");
    let file_content = "shared file content";

    // Upload with specific content
    let boundary = "TestBoundary1234";
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
                    "shared.txt",
                    "text/plain",
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

    let share_json = create_share_token_for_file(app.clone(), &token, &file_id).await;
    let download_url = share_json["download_url"].as_str().unwrap().to_string();

    // Download via shared URL — no auth required
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&download_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let downloaded = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(downloaded.as_ref(), file_content.as_bytes());
}

#[tokio::test]
async fn test_download_shared_file_expired() {
    tokio::fs::create_dir_all("./uploads").await.unwrap();
    let pool = test_pool().await;
    let alice_id = create_test_user(&pool, "alice", "password123").await;
    let app = make_app(pool.clone());
    let token = make_jwt(alice_id, "alice");

    let file_id = upload_file_for_user(app.clone(), &token, "expiring.txt").await;
    let file_uuid: Uuid = file_id.parse().unwrap();

    // Insert a share token that is already expired
    let share_token = Uuid::new_v4();
    let expired_at = Utc::now() - Duration::hours(1);
    sqlx::query!(
        "INSERT INTO share_tokens (token, file_id, expires_at) VALUES ($1, $2, $3)",
        share_token,
        file_uuid,
        expired_at,
    )
    .execute(&pool)
    .await
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/files/shared/{}", share_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}
