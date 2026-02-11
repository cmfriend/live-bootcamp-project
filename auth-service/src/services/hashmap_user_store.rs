use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

// TODO: Create a new struct called `HashmapUserStore` containing a `users` field
// which stores a `HashMap`` of email `String`s mapped to `User` objects.
// Derive the `Default` trait for `HashmapUserStore`.
#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        use std::collections::hash_map::Entry;
    
        match self.users.entry(user.email.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(user);
                Ok(())
            }
            Entry::Occupied(_) => Err(UserStoreError::UserAlreadyExists),
        }
    }

    // TODO: Implement a public method called `get_user`, which takes an
    // immutable reference to self and an email string slice as arguments.
    // This function should return a `Result` type containing either a
    // `User` object or a `UserStoreError`.
    // Return `UserStoreError::UserNotFound` if the user can not be found.
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self
            .users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    // TODO: Implement a public method called `validate_user`, which takes an
    // immutable reference to self, an email string slice, and a password string slice
    // as arguments. `validate_user` should return a `Result` type containing either a
    // unit type `()` if the email/password passed in match an existing user, or a `UserStoreError`.
    // Return `UserStoreError::UserNotFound` if the user can not be found.
    // Return `UserStoreError::InvalidCredentials` if the password is incorrect.
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        self
            .users
            .get(email)
            .ok_or(UserStoreError::UserNotFound)
            .and_then(
                |user| if &user.email == email && &user.password == password {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            )
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse("bob@example.com".to_string()).unwrap();
        let password = Password::parse("password".to_string()).unwrap();

        let bob = User::new(email, password, true);
        let bob_clone = bob.clone();

        assert!(user_store.add_user(bob).await.is_ok());

        assert_eq!(user_store.add_user(bob_clone).await.unwrap_err(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();

        let bob_email = Email::parse("bob@example.com".to_string()).unwrap();
        let bob_password = Password::parse("password".to_string()).unwrap();
        let bob_requires_2fa = true;
        let bob = User::new(bob_email.clone(), bob_password, bob_requires_2fa);

        assert_eq!(user_store.get_user(&bob.email).await.unwrap_err(), UserStoreError::UserNotFound);

        user_store.users.insert(bob_email.clone(), bob.clone());

        assert_eq!(user_store.get_user(&bob_email).await.unwrap(), bob);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();

        let bob_email = Email::parse("bob@example.com".to_string()).unwrap();
        let bob_password = Password::parse("password".to_string()).unwrap();
        let bob_requires_2fa = true;
        let bob = User::new(bob_email.clone(), bob_password.clone(), bob_requires_2fa);

        let _ = user_store.add_user(bob.clone()).await;

        assert!(user_store.validate_user(&bob_email, &bob_password).await.is_ok());

        let missing_user = Email::parse("somebodyelse@example.com".to_string()).unwrap();
        let missing_user_password = Password::parse("blahblahblah".to_string()).unwrap();
        assert_eq!(user_store.validate_user(&missing_user, &missing_user_password).await.unwrap_err(), UserStoreError::UserNotFound);
    }
}
