use std::collections::HashMap;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some(code) => Ok(code.clone()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_code_successfully_adds_code() {
        let mut store = HashmapTwoFACodeStore::default();

        assert!(store.codes.is_empty());

        let email = Email::parse("bob@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;

        assert!(result.is_ok());
        assert!(store.codes.len() == 1);
        assert_eq!(store.codes.get(&email), Some(&(login_attempt_id, code)));
    }

    #[tokio::test]
    async fn remove_code_successfully_removes_existing_code() {
        let mut store = HashmapTwoFACodeStore::default();

        let email = Email::parse("bob@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        store
            .codes
            .insert(email.clone(), (login_attempt_id.clone(), code.clone()));

        assert!(store.codes.len() == 1);
        assert_eq!(store.codes.get(&email), Some(&(login_attempt_id, code)));

        let result = store.remove_code(&email).await;

        assert!(result.is_ok());
        assert!(store.codes.get(&email).is_none());
    }

    #[tokio::test]
    async fn remove_code_fails_on_missing_code() {
        let mut store = HashmapTwoFACodeStore::default();

        assert!(store.codes.is_empty());

        let email = Email::parse("bob@example.com".to_string()).unwrap();

        let result = store.remove_code(&email).await;

        assert_eq!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound));
    }

    #[tokio::test]
    async fn get_code_successfully_gets_existing_code() {
        let mut store = HashmapTwoFACodeStore::default();

        let email = Email::parse("bob@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        store
            .codes
            .insert(email.clone(), (login_attempt_id.clone(), code.clone()));

        let result = store.get_code(&email).await;

        assert_eq!(result, Ok((login_attempt_id, code)));
        assert_eq!(store.codes.len(), 1);
    }

    #[tokio::test]
    async fn get_code_fails_on_missing_code() {
        let store = HashmapTwoFACodeStore::default();

        let email = Email::parse("bob@example.com".to_string()).unwrap();
        let result = store.get_code(&email).await;

        assert_eq!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound));
    }
}
