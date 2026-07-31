/*!
# `jwt-authorization` Request Guard for Rocket Framework

This crate provides a procedural macro to create request guards used for authorization.

Deriving `JWT` turns a claims struct into a Rocket request guard which reads a JSON Web Token from a request, verifies its signature, and validates its claims (`exp` by default).

## Example

```rust,no_run
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rocket::{get, http::CookieJar, routes};
use rocket_jwt_authorization::prelude::*;
use serde::{Deserialize, Serialize};

static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, header, cookie = "access_token")]
struct UserAuth {
    exp: u64,
    id:  i32,
}

#[get("/login")]
fn login(cookies: &CookieJar) -> &'static str {
    let user_auth = UserAuth {
        exp: (SystemTime::now() + Duration::from_secs(3600))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        id:  1,
    };

    // Writes an `HttpOnly` + `SameSite=Strict` cookie which expires together with the token.
    user_auth.add_cookie(cookies).unwrap();

    "Logged in."
}

#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}

#[get("/logout")]
fn logout(cookies: &CookieJar) -> &'static str {
    UserAuth::remove_cookie(cookies);

    "Logged out."
}

fn main() {
    let _rocket = rocket::build().mount("/", routes![index, login, logout]);
}
```

A token can also be created and verified without Rocket:

```rust
use rocket_jwt_authorization::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize, JWT)]
#[jwt(key = "cc818bd5-6d16-4a67-b109-43d22d252f88")]
struct UserAuth {
    exp: u64,
    id:  i32,
}

let user_auth = UserAuth {
    exp: jsonwebtoken::get_current_timestamp() + 3600,
    id:  1,
};

let token = user_auth.sign().unwrap();

assert_eq!(user_auth, UserAuth::verify(token).unwrap());
```

## Options of the `jwt` attribute

| Option | Default | Description |
| ------ | ------- | ----------- |
| `key = EXPR` | | The shared secret, only for the `HS*` algorithms. Anything which is `AsRef<[u8]>` works. |
| `encoding_key = EXPR` | | An [`EncodingKey`], needed instead of `key` by the asymmetric algorithms. |
| `decoding_key = EXPR` | | A [`DecodingKey`], needed instead of `key` by the asymmetric algorithms. |
| `algorithm = NAME` | `HS256` | One of `HS256`, `HS384`, `HS512`, `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `EdDSA`. |
| `header` | used when no source is given | Reads `Authorization: Bearer <token>`. Written as `header(name = "x-auth", scheme = "Token")` to change the header or the scheme. |
| `cookie = "name"` | | Reads a cookie. Written as `cookie(name = "…", path = "…", secure = true, http_only = false, same_site = "lax", max_age = false)` to change its attributes. |
| `query = "name"` | | Reads a query parameter. |
| `leeway = 60` | `60` | The number of seconds of clock skew allowed when `exp` and `nbf` are validated. |
| `validate_exp = false` | `true` | Whether `exp` is validated. |
| `validate_nbf = true` | `false` | Whether `nbf` is validated. |
| `issuer = "…"` | | The accepted `iss` claims. An array accepts several of them. |
| `audience = "…"` | | The accepted `aud` claims. An array accepts several of them. |
| `required_claims = ["exp"]` | `["exp"]` | The claims a token has to carry. |
| `forward` | | Makes a failing guard forward with `401 Unauthorized` instead of erroring with it. |

Sources are tried in the order they are written. When no source is given, `header` is used.

## Crypto backend

[`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) needs exactly one crypto backend. This crate enables the pure Rust one by default; to use AWS-LC instead, turn the default features off.

```toml
[dependencies]
rocket-jwt-authorization = { version = "0.3", default-features = false, features = ["aws_lc_rs", "use_pem"] }
```
*/

mod cookie;
mod error;

pub use cookie::CookieConfig;
pub use error::JwtGuardError;
pub use jsonwebtoken::{
    self, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors, errors::Error,
};
use rocket::{
    http::{Cookie, CookieJar},
    request::Request,
};
pub use rocket_jwt_authorization_derive::JWT;
use serde::{Serialize, de::DeserializeOwned};

pub mod prelude {
    pub use super::{FromJwtRequest, JWT, Jwt, JwtCookie};
}

#[doc(hidden)]
pub mod __private {
    pub use std::sync::OnceLock;

    pub use rocket;

    /// Reads the token out of a header value like `Bearer abc`. The scheme is matched case-insensitively, as RFC 7235 requires.
    #[inline]
    pub fn scheme_token<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
        if scheme.is_empty() {
            return Some(value.trim());
        }

        let (found, rest) = value.split_at_checked(scheme.len())?;

        if !found.eq_ignore_ascii_case(scheme) {
            return None;
        }

        Some(rest.strip_prefix(' ')?.trim_start())
    }
}

/// A set of claims which can be signed into a token and verified back. Implemented by `#[derive(JWT)]`.
pub trait Jwt: Serialize + DeserializeOwned + Sized {
    fn jwt_encoding_key() -> &'static EncodingKey;

    fn jwt_decoding_key() -> &'static DecodingKey;

    fn jwt_header() -> &'static Header;

    fn jwt_validation() -> &'static Validation;

    /// Signs these claims into a token.
    #[inline]
    fn sign(&self) -> Result<String, Error> {
        jsonwebtoken::encode(Self::jwt_header(), self, Self::jwt_encoding_key())
    }

    /// Verifies the signature of a token and validates its claims.
    #[inline]
    fn verify<T: AsRef<[u8]>>(token: T) -> Result<Self, Error> {
        jsonwebtoken::decode::<Self>(token, Self::jwt_decoding_key(), Self::jwt_validation())
            .map(|token_data| token_data.claims)
    }

    /// The `exp` claim, if there is one. It is what [`JwtCookie`] uses to set `Max-Age`.
    #[inline]
    fn expiration(&self) -> Option<u64> {
        serde_json::to_value(self).ok()?.get("exp")?.as_u64()
    }
}

/// Reads a token from a request without going through Rocket's outcomes. Implemented by `#[derive(JWT)]`.
pub trait FromJwtRequest: Jwt {
    /// Tries every source of the `jwt` attribute in order.
    fn from_jwt_request(request: &Request<'_>) -> Result<Self, JwtGuardError>;
}

/// Stores a token in a cookie. Implemented by `#[derive(JWT)]` when the `jwt` attribute has a `cookie` source.
pub trait JwtCookie: Jwt {
    fn jwt_cookie_config() -> &'static CookieConfig;

    /// Signs these claims into a cookie without adding it to a jar.
    #[inline]
    fn to_cookie(&self) -> Result<Cookie<'static>, Error> {
        Ok(Self::jwt_cookie_config().build_cookie(self.sign()?, self.expiration()))
    }

    #[inline]
    fn add_cookie(&self, cookies: &CookieJar<'_>) -> Result<(), Error> {
        cookies.add(self.to_cookie()?);

        Ok(())
    }

    #[inline]
    fn remove_cookie(cookies: &CookieJar<'_>) {
        cookies.remove(Self::jwt_cookie_config().build_removal_cookie());
    }
}
