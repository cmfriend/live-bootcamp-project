use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode},
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

    let user = match user_store.get_user(&email).await.map_err(|_| AuthAPIError::IncorrectCredentials) {
        Ok(user) => user,
        Err(e) => return (jar, Err(e)),
    };

    let auth_cookie = match generate_auth_cookie(&email).map_err(|_| AuthAPIError::UnexpectedError) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(e)),
    };

    let updated_jar = jar.add(auth_cookie);

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(updated_jar, &user.email, &state).await,
        false => handle_no_2fa(&user.email, updated_jar).await,
    }
}

async fn handle_2fa(
    jar: CookieJar,
    email: &Email,
    state: &AppState
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    if state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), code)
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)
        .is_err() {
            return (jar, Err(AuthAPIError::UnexpectedError));
        }

    // Finally, we need to return the login attempt ID to the client
    let response =
        Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
            message: "2FA required".to_owned(),
            login_attempt_id: login_attempt_id.as_ref().to_string(),
        }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

async fn handle_no_2fa(
    _email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    (
        jar,
        Ok(
            (
                StatusCode::OK,
                Json(LoginResponse::RegularAuth)
            )
        )
    )
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
