use std::{
    error::Error as StdError,
    fmt::{self, Display, Formatter},
};

use jsonwebtoken::errors::Error;

/// The reason why a JWT request guard did not succeed.
#[derive(Debug, Clone)]
pub enum JwtGuardError {
    /// No token could be found in any of the sources of the request.
    Missing,
    /// A token was found but it could not be verified. Use `Error::kind` to tell an expired token from a forged one.
    Invalid(Error),
}

impl Display for JwtGuardError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            JwtGuardError::Missing => f.write_str("no JWT can be found in the request"),
            JwtGuardError::Invalid(error) => Display::fmt(error, f),
        }
    }
}

impl StdError for JwtGuardError {
    #[inline]
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            JwtGuardError::Missing => None,
            JwtGuardError::Invalid(error) => Some(error),
        }
    }
}
