use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);

        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_token_succeeds() {
        let mut token_store = HashsetBannedTokenStore::default();

        assert!(token_store.store_token("some token string".to_string()).await.is_ok());
    }

    #[tokio::test]
    async fn contains_token_returns_true_for_found_token() {
        let mut token_store = HashsetBannedTokenStore::default();

        let token = "some token value".to_string();

        token_store.tokens.insert(token.clone());

        assert!(token_store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn contains_token_returns_false_for_missing_token() {
        let mut token_store = HashsetBannedTokenStore::default();

        assert!(!token_store.contains_token("some token value").await.unwrap());

        let token = "some token value".to_string();

        token_store.tokens.insert(token.clone());

        assert!(!token_store.contains_token("some other token value").await.unwrap());
    }
}
