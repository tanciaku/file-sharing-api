use axum::{http::StatusCode, response::IntoResponse};

pub enum AppError {
    Database,
    NotFound(String),
    BadRequest,
    //Conflict(String),
    InternalError,
    Unauthorized,
    //Forbidden,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::Database => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal error occurred".to_string()
            )
                .into_response(),
            AppError::NotFound(id) => (
                StatusCode::NOT_FOUND,
                format!("Not found: {}", id),
            )
                .into_response(),
            AppError::BadRequest => (
                StatusCode::BAD_REQUEST,
                "...".to_string(),
            )
                .into_response(),
            //AppError::Conflict(msg) => (StatusCode::CONFLICT, msg).into_response(),
            AppError::InternalError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong".to_string(),
            )
                .into_response(),
            AppError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()).into_response()
            }
            //AppError::Forbidden => (
            //    StatusCode::FORBIDDEN,
            //    "You do not have permission to perform this action".to_string(),
            //)
            //    .into_response(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(_: sqlx::Error) -> Self {
        AppError::Database
    }
}