use super::{Email, Password, User};
use color_eyre::eyre::{eyre, Report, Result};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;

    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn store_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError>;

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl LoginAttemptId {
    pub fn parse(id: SecretString) -> Result<Self> {
        let id = uuid::Uuid::parse_str(id.expose_secret())
            .map_err(|_| eyre!("Invalid login attempt id"))?;
        Ok(Self(SecretString::new(id.to_string().into_boxed_str())))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(SecretString::new(
            uuid::Uuid::new_v4().to_string().into_boxed_str(),
        ))
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(SecretString);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFACode {
    pub fn parse(code: SecretString) -> Result<Self> {
        let code_as_u32 = code.expose_secret().parse::<u32>()?;
        if (100_000..=999_999).contains(&code_as_u32) {
            Ok(Self(code))
        } else {
            Err(eyre!("Invalid email code"))
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        Self(SecretString::new(
            rand::rng()
                .random_range(100_000..=999_999)
                .to_string()
                .into_boxed_str(),
        ))
    }
}

impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}
