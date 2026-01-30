use super::{Email, Password};

// The User struct should contain 3 fields. email, which is a String; 
// password, which is also a String; and requires_2fa, which is a boolean. 
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa,
        }
    }
}
