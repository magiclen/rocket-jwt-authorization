use std::borrow::Cow;

use jsonwebtoken::errors::{Error, ErrorKind};

use crate::Jwt;

/// The `WWW-Authenticate` challenge which a `401 Unauthorized` answer carries.
#[derive(Debug, Clone)]
pub struct ChallengeConfig {
    scheme: Cow<'static, str>,
    realm:  Option<Cow<'static, str>>,
}

impl ChallengeConfig {
    /// Creates a config whose challenge names the given scheme and no realm.
    #[inline]
    pub fn new<S: Into<Cow<'static, str>>>(scheme: S) -> Self {
        ChallengeConfig {
            scheme: scheme.into(), realm: None
        }
    }

    /// Sets `realm`, which tells the client which set of resources the token would let it reach.
    #[inline]
    pub fn realm<R: Into<Cow<'static, str>>>(mut self, realm: R) -> Self {
        self.realm = Some(realm.into());

        self
    }

    /// The scheme of the challenge, which is the one the `header` source expects.
    #[inline]
    pub fn scheme(&self) -> &str {
        self.scheme.as_ref()
    }

    /// Builds the value of a `WWW-Authenticate` header.
    /// A description turns the challenge into the `invalid_token` error of RFC 6750, so leave it out when the request simply came without a token.
    /// Returns `None` when the scheme is empty, because a challenge cannot be written without one.
    pub(crate) fn header_value(&self, description: Option<&str>) -> Option<String> {
        if self.scheme.is_empty() {
            return None;
        }

        let mut value = self.scheme.as_ref().to_string();

        if let Some(realm) = self.realm.as_ref() {
            value.push_str(" realm=\"");
            push_quoted(&mut value, realm);
            value.push('"');
        }

        if let Some(description) = description {
            value.push_str(if self.realm.is_some() { ", " } else { " " });
            value.push_str("error=\"invalid_token\", error_description=\"");
            push_quoted(&mut value, description);
            value.push('"');
        }

        Some(value)
    }
}

/// Writes the body of a quoted string, escaping what RFC 9110 does not allow to stand on its own.
/// A control character cannot be escaped at all, so it is dropped rather than written into a broken header.
fn push_quoted(value: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                value.push('\\');
                value.push(c);
            },
            c if c.is_control() => (),
            c => value.push(c),
        }
    }
}

/// Says why a token was rejected, in words a client can act on.
/// The set of answers is fixed, so that neither an internal detail nor a character which would break a quoted string can reach a header.
pub(crate) fn error_description(error: &Error) -> &'static str {
    match error.kind() {
        ErrorKind::ExpiredSignature => "the token has expired",
        ErrorKind::ImmatureSignature => "the token is not valid yet",
        ErrorKind::InvalidSignature => "the signature is invalid",
        ErrorKind::InvalidIssuer => "the issuer is not accepted",
        ErrorKind::InvalidAudience => "the audience is not accepted",
        ErrorKind::InvalidSubject => "the subject is not accepted",
        ErrorKind::MissingRequiredClaim(_) => "a required claim is missing",
        ErrorKind::InvalidAlgorithm => "the algorithm is not accepted",
        _ => "the token is malformed",
    }
}

/// Answers a failed request guard with a challenge. Implemented by `#[derive(JWT)]` when the `jwt` attribute has a `header` source.
///
/// The challenge only reaches the client through [`JwtFairing`](crate::JwtFairing), because Rocket answers a failed guard from a catcher, which knows nothing about the guard.
pub trait JwtChallenge: Jwt {
    /// The challenge to send back, built from the `header` source and the `realm` option of the `jwt` attribute.
    fn jwt_challenge_config() -> &'static ChallengeConfig;
}
