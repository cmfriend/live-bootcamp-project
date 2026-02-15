use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    let _ = match validate_token(&token, state.banned_token_store.clone())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)
    {
        Ok(claims) => claims,
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    };

    let jar = jar.remove(JWT_COOKIE_NAME);

    if state
        .banned_token_store
        .write()
        .await
        .store_token(token)
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    (jar, Ok(StatusCode::OK))
}
