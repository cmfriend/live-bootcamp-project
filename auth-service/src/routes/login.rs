use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials) {
        Ok(email) => email,
        Err(e) => return (jar, Err(e)),
    };

    let password = match Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials) {
        Ok(password) => password,
        Err(e) => return (jar, Err(e)),
    };

    let user_store = &state.user_store.read().await;

    if user_store.validate_user(&email, &password).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let _ = match user_store.get_user(&email).await.map_err(|_| AuthAPIError::IncorrectCredentials) {
        Ok(user) => user,
        Err(e) => return (jar, Err(e)),
    };

    let auth_cookie = match generate_auth_cookie(&email).map_err(|_| AuthAPIError::UnexpectedError) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(e)),
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
