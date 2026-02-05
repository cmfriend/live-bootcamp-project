pub enum AuthAPIError {
    IncorrectCredentials,
    InvalidCredentials,
    InvalidToken,
    MissingToken,
    UnexpectedError,
    UserAlreadyExists,
}
