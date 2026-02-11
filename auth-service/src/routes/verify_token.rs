use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::auth::validate_token
};
use serde::Deserialize;

pub async fn verify_token(State(state): State<AppState>, Json(request): Json<VerifyTokenRequest>) -> Result<impl IntoResponse, AuthAPIError> {
    validate_token(&request.token, state.banned_token_store.clone()).await.map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}