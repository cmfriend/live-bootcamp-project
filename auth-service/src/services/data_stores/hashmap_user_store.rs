use std::collections::HashMap;

use crate::domain::{Email, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        use std::collections::hash_map::Entry;

        match self.users.entry(user.email.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(user);
                Ok(())
            }
            Entry::Occupied(_) => Err(UserStoreError::UserAlreadyExists),
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user: &User = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::HashedPassword;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse("bob@example.com".to_string()).unwrap();
        let password = HashedPassword::parse("password".to_string()).await.unwrap();

        let bob = User::new(email, password, true);
        let bob_clone = bob.clone();

        assert!(user_store.add_user(bob).await.is_ok());

        assert_eq!(
            user_store.add_user(bob_clone).await.unwrap_err(),
            UserStoreError::UserAlreadyExists
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();

        let bob_email = Email::parse("bob@example.com".to_string()).unwrap();
        let bob_password = HashedPassword::parse("password".to_string()).await.unwrap();
        let bob_requires_2fa = true;
        let bob = User::new(bob_email.clone(), bob_password, bob_requires_2fa);

        assert_eq!(
            user_store.get_user(&bob.email).await.unwrap_err(),
            UserStoreError::UserNotFound
        );

        user_store.users.insert(bob_email.clone(), bob.clone());

        assert_eq!(user_store.get_user(&bob_email).await.unwrap(), bob);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();

        let bob_email = Email::parse("bob@example.com".to_string()).unwrap();
        let bob_raw_password = "password";
        let bob_password = HashedPassword::parse(bob_raw_password.to_string())
            .await
            .unwrap();
        let bob_requires_2fa = true;
        let bob = User::new(bob_email.clone(), bob_password.clone(), bob_requires_2fa);

        let _ = user_store.add_user(bob.clone()).await;

        assert!(user_store
            .validate_user(&bob_email, bob_raw_password)
            .await
            .is_ok());

        let missing_user = Email::parse("somebodyelse@example.com".to_string()).unwrap();
        let missing_raw_password = "blahblahblah";
        assert_eq!(
            user_store
                .validate_user(&missing_user, missing_raw_password)
                .await
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }
}
