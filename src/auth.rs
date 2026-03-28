use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::request::Parts,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::{AppState, error::AppError};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: i64,
    pub exp: usize,
}

pub struct AuthUser(pub Claims);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized)?;

        Ok(AuthUser(token_data.claims))
    }
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let user = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    let parsed_hash =
        PasswordHash::new(&user.password_hash).map_err(|_| AppError::InternalError)?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::Unauthorized)?;

    let exp = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: payload.username,
        user_id: user.id,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|_| AppError::InternalError)?;

    Ok(Json(LoginResponse { token }))
}
