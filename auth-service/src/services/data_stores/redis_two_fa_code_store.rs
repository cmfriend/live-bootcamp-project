use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Storing 2FA code in Redis", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);

        let raw_tuple = TwoFATuple(
            login_attempt_id.as_ref().expose_secret().to_string(),
            code.as_ref().expose_secret().to_string(),
        );

        let tuple = serde_json::to_string(&raw_tuple)
            .wrap_err("failed to serialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        self.conn
            .write()
            .await
            .set_ex(key, tuple, TEN_MINUTES_IN_SECONDS)
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)
    }

    #[tracing::instrument(name = "Removing 2FA code from Redis", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        self.conn
            .write()
            .await
            .del(key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)
    }

    #[tracing::instrument(name = "Retrieving 2FA code from Redis", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        match self.conn.write().await.get::<_, String>(&key) {
            Ok(value) => {
                let data: TwoFATuple = serde_json::from_str(&value)
                    .wrap_err("failed to deserialize 2FA tuple")
                    .map_err(TwoFACodeStoreError::UnexpectedError)?;

                let login_attempt_id =
                    LoginAttemptId::parse(SecretString::new(data.0.into_boxed_str()))
                        .map_err(TwoFACodeStoreError::UnexpectedError)?;

                let email_code = TwoFACode::parse(SecretString::new(data.1.into_boxed_str()))
                    .map_err(TwoFACodeStoreError::UnexpectedError)?;

                Ok((login_attempt_id, email_code))
            }
            Err(_) => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}
