#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(s: String) -> Result<Self, String> {
        if s.len() < 8 {
            return Err("Invalid password provided.".to_string());
        }

        Ok(Self(s))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;

    #[test]
    fn empty_password_not_valid() {
        assert!(Password::parse("".to_string()).is_err());
    }

    #[test]
    fn too_short_password_not_valid() {
        assert!(Password::parse("abc".to_string()).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password)
        }
    }
    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0).is_ok()
    }
}