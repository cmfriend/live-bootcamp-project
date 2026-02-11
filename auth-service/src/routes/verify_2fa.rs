use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use axum_extra::extract::CookieJar;
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};
use serde::Deserialize;

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials) {
        Ok(email) => email,
        Err(e) => return (jar, Err(e)),
    };

    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id).map_err(|_| AuthAPIError::InvalidCredentials) {
        Ok(login_attempt_id) => login_attempt_id,
        Err(e) => return (jar, Err(e)),
    };

    let two_fa_code = match TwoFACode::parse(request.two_fa_code).map_err(|_| AuthAPIError::InvalidCredentials) {
        Ok(two_fa_code) => two_fa_code,
        Err(e) => return (jar, Err(e)),
    };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let (stored_login_attempt_id, stored_two_fa_code) =
        match two_fa_code_store
            .get_code(&email)
            .await
            .map_err(|_| AuthAPIError::IncorrectCredentials) {
                Ok((stored_login_attempt_id, stored_two_fa_code)) => (stored_login_attempt_id, stored_two_fa_code),
                Err(e) => return (jar, Err(e)),
            };

    if login_attempt_id != stored_login_attempt_id || two_fa_code != stored_two_fa_code {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    if two_fa_code_store.remove_code(&email).await.is_err() {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    let auth_cookie = match generate_auth_cookie(&email).map_err(|_| AuthAPIError::UnexpectedError) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(e)),
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}
