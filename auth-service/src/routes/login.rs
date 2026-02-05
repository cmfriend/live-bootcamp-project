use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password}
};

pub async fn login(State(state): State<AppState>, Json(request): Json<LoginRequest>) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let password = Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = &state.user_store.read().await;

    user_store.validate_user(&email, &password).await.map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let _ = user_store.get_user(&email).await.map_err(|_| AuthAPIError::IncorrectCredentials)?;

    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
