use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

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

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) => {
                if user.password.eq(password) {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            }
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User {
            email: Email::parse(SecretString::new(
                "test@example.com".to_owned().into_boxed_str(),
            ))
            .unwrap(),
            password: Password::parse(SecretString::new("password".to_string().into_boxed_str()))
                .unwrap(),
            requires_2fa: false,
        };

        // Test adding a new user
        let result = user_store.add_user(user.clone()).await;
        assert!(result.is_ok());

        // Test adding an existing user
        let result = user_store.add_user(user).await;
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();

        let user = User {
            email: email.clone(),
            password: Password::parse(SecretString::new("password".to_owned().into_boxed_str()))
                .unwrap(),
            requires_2fa: false,
        };

        // Test getting a user that exists
        user_store.users.insert(email.clone(), user.clone());
        let result = user_store.get_user(&email).await;
        assert_eq!(result, Ok(user));

        // Test getting a user that doesn't exist
        let result = user_store
            .get_user(
                &Email::parse(SecretString::new(
                    "nonexistent@example.com".to_owned().into_boxed_str(),
                ))
                .unwrap(),
            )
            .await;

        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let password =
            Password::parse(SecretString::new("password".to_owned().into_boxed_str())).unwrap();

        let user = User {
            email: email.clone(),
            password: password.clone(),
            requires_2fa: false,
        };

        // Test validating a user that exists with correct password
        user_store.users.insert(email.clone(), user.clone());
        let result = user_store.validate_user(&email, &password).await;
        assert_eq!(result, Ok(()));

        // Test validating a user that exists with incorrect password
        let wrong_password = Password::parse(SecretString::new(
            "wrongpassword".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let result = user_store.validate_user(&email, &wrong_password).await;
        assert_eq!(result, Err(UserStoreError::InvalidCredentials));

        // Test validating a user that doesn't exist
        let result = user_store
            .validate_user(
                &Email::parse(SecretString::new(
                    "nonexistent@example.com".to_owned().into_boxed_str(),
                ))
                .unwrap(),
                &password,
            )
            .await;

        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }
}
