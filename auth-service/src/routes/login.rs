use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let password =
        match Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials) {
            Ok(password) => password,
            Err(e) => return (jar, Err(e)),
        };

    let email = match Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials) {
        Ok(email) => email,
        Err(e) => return (jar, Err(e)),
    };

    let user_store = &state.user_store.read().await;

    if user_store.validate_user(&email, &password).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let user = match user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)
    {
        Ok(user) => user,
        Err(e) => return (jar, Err(e)),
    };

    match user.requires_2fa {
        true => handle_2fa(jar, &user.email, &state).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

#[tracing::instrument(name = "Handle 2FA flow", skip_all)]
async fn handle_2fa(
    jar: CookieJar,
    email: &Email,
    state: &AppState,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    if let Err(e) = state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), code.clone())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    if let Err(e) = state
        .email_client
        .send_email(email, "2FA Code", code.as_ref().expose_secret())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e)));
    }

    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().expose_secret().to_string(),
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

#[tracing::instrument(name = "Handle non-2FA flow", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: SecretString,
    password: SecretString,
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
