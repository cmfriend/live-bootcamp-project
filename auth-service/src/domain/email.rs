use validator::ValidateEmail;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Email(String);

impl Email {
    pub fn parse(s: String) -> Result<Self, String> {
        if !s.validate_email() {
            return Err(format!("{} is not a valid email.", s));
        }

        Ok(Self(s))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;

    #[test]
    fn empty_string_is_invalid() {
        let email = "".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn string_missing_at_symbol_is_invalid() {
        let email = "bobatexample.com".to_string();
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let email = SafeEmail().fake_with_rng(&mut rng);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(valid_email.0).is_ok()
    }
}
