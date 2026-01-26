use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

// TODO: Create a new struct called `HashmapUserStore` containing a `users` field
// which stores a `HashMap`` of email `String`s mapped to `User` objects.
// Derive the `Default` trait for `HashmapUserStore`.
#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
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
    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self
            .users
            .get(email)
            .ok_or(UserStoreError::UserNotFound)
            .map(|user| User::new(user.email.clone(), user.password.clone(), user.requires_2fa))
    }

    // TODO: Implement a public method called `validate_user`, which takes an
    // immutable reference to self, an email string slice, and a password string slice
    // as arguments. `validate_user` should return a `Result` type containing either a
    // unit type `()` if the email/password passed in match an existing user, or a `UserStoreError`.
    // Return `UserStoreError::UserNotFound` if the user can not be found.
    // Return `UserStoreError::InvalidCredentials` if the password is incorrect.
    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        self
            .users
            .get(email)
            .ok_or(UserStoreError::UserNotFound)
            .and_then(
                |user| if user.email == email && user.password == password {
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

        let bob = User::new("bob@example.com".to_string(), "bobspassword123".to_string(), true);
        let bob_clone = bob.clone();

        assert!(user_store.add_user(bob).is_ok());

        assert_eq!(user_store.add_user(bob_clone).unwrap_err(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();

        let bob_email = "bob@example.com";
        let bob_password = "bobspassword123";
        let bob_requires_2fa = true;
        let bob = User::new(bob_email.to_string(), bob_password.to_string(), bob_requires_2fa);

        assert_eq!(user_store.get_user(bob_email).unwrap_err(), UserStoreError::UserNotFound);

        let _ = user_store.add_user(bob.clone());

        assert_eq!(user_store.get_user(bob_email).unwrap(), bob);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();

        let bob_email = "bob@example.com";
        let bob_password = "bobspassword123";
        let bob_requires_2fa = true;
        let bob = User::new(bob_email.to_string(), bob_password.to_string(), bob_requires_2fa);

        let _ = user_store.add_user(bob.clone());

        assert!(user_store.validate_user(bob_email, bob_password).is_ok());

        assert_eq!(user_store.validate_user(bob_email, "notbobspassword321").unwrap_err(), UserStoreError::InvalidCredentials);

        assert_eq!(user_store.validate_user("somebodyelse@example.com", "somepassword").unwrap_err(), UserStoreError::UserNotFound);
    }
}
