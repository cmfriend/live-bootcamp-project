use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};
use secrecy::{ExposeSecret, SecretString};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_string());

        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_token_succeeds() {
        let mut token_store = HashsetBannedTokenStore::default();

        assert!(token_store
            .store_token(SecretString::new(
                "some token value".to_owned().into_boxed_str()
            ))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn contains_token_returns_true_for_found_token() {
        let mut token_store = HashsetBannedTokenStore::default();

        let token = SecretString::new("some token value".to_owned().into_boxed_str());

        token_store.tokens.insert(token.expose_secret().to_string());

        assert!(token_store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn contains_token_returns_false_for_missing_token() {
        let mut token_store = HashsetBannedTokenStore::default();

        assert!(!token_store
            .contains_token(&SecretString::new(
                "some token value".to_owned().into_boxed_str()
            ))
            .await
            .unwrap());

        let token = "some token value".to_string();

        token_store.tokens.insert(token.clone());

        assert!(!token_store
            .contains_token(&SecretString::new(
                "some other token value".to_owned().into_boxed_str()
            ))
            .await
            .unwrap());
    }
}
