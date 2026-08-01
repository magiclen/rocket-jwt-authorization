/*!
# `jwt-authorization` Request Guard for Rocket Framework

Turn a claims struct into a Rocket request guard.

`#[derive(JWT)]` writes the code which pulls a JSON Web Token out of a request, checks its signature, and validates its claims. A route which asks for the struct runs only after all of that has succeeded, so a handler never has to deal with an unauthenticated request. Anything else gets `401 Unauthorized` before the handler is reached.

## Getting started

Add two things to a struct: the `serde` derives, so the claims can be turned into JSON, and `JWT` with a `jwt` attribute which says how tokens are signed and where they come from.

```rust,no_run
use rocket::{get, launch, routes};
use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

// Read this from the environment in a real application, and never commit it.
static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY)]
struct UserAuth {
    exp: u64,
    id:  i32,
}

#[get("/login")]
fn login() -> String {
    let user_auth = UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600,
        id:  1,
    };

    // `sign` comes from the `Jwt` trait, which the derive implements.
    user_auth.sign().unwrap()
}

// `UserAuth` is a request guard here. Without a valid token this function is never called.
#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, login])
}
```

By default the token is read from `Authorization: Bearer <token>`. The `exp` claim is validated on every request, so an expired token cannot get in.

## Storing the token in a cookie

Adding a `cookie` source also gives the type the [`JwtCookie`] trait, which knows how to write and clear the cookie.

```rust,no_run
# use rocket::{get, http::CookieJar, routes};
# use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
# use serde::{Deserialize, Serialize};
# static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, cookie = "access_token")]
struct UserAuth {
    exp: u64,
    id:  i32,
}

#[get("/login")]
fn login(cookies: &CookieJar) -> &'static str {
    let user_auth = UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600,
        id:  1,
    };

    user_auth.add_cookie(cookies).unwrap();

    "Logged in."
}

#[get("/logout")]
fn logout(cookies: &CookieJar) -> &'static str {
    UserAuth::remove_cookie(cookies);

    "Logged out."
}
# fn main() {}
```

The cookie is `HttpOnly`, `SameSite=Strict` and `Path=/`, and its `Max-Age` follows the `exp` claim, so it disappears from the browser when the token stops being valid. Use `cookie(...)` instead of `cookie = "…"` to change any of that.

When a cookie holds a token which cannot be verified, the guard also clears the cookie, because the browser would otherwise keep sending a token which is never going to work again. Attaching [`JwtFairing`] is what makes that happen on a `401` answer as well; see the section below.

## Answering with `WWW-Authenticate`

RFC 7235 asks every `401 Unauthorized` to say how a client is supposed to authenticate. Rocket answers a failed guard from a catcher, and a catcher knows nothing about the guard which failed, so the challenge needs one fairing to carry it across.

```rust,no_run
# use rocket::{get, launch, routes};
# use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
# use serde::{Deserialize, Serialize};
# static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, realm = "api")]
struct UserAuth {
    exp: u64,
    id:  i32,
}

#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}

#[launch]
fn rocket() -> _ {
    rocket::build().attach(JwtFairing).mount("/", routes![index])
}
```

A request which never carried a token is answered with a bare challenge, because RFC 6750 asks a server not to report an error to a client which did not try in the first place. Everything else is an `invalid_token` with a short description of what was wrong.

| Request | `WWW-Authenticate` |
| ------- | ------------------ |
| no token | `Bearer realm="api"` |
| expired token | `Bearer realm="api", error="invalid_token", error_description="the token has expired"` |

The descriptions come from a fixed list, so nothing an attacker controls and no internal detail can reach the header. The scheme is the one the `header` source expects, and `realm` is optional; without it a challenge is just `Bearer`.

The same fairing also puts back the removal of a cookie which held an unusable token, which Rocket otherwise drops on its way to the catcher. A guard which is written as `Option<T>`, or which forwards to a route that answers normally, clears the cookie without the fairing.

## Three ways to write the guard

| In the route | Behaviour |
| ------------ | --------- |
| `user_auth: UserAuth` | Required. A missing or invalid token answers `401 Unauthorized` and the handler is skipped. |
| `user_auth: Option<UserAuth>` | Optional. A missing or invalid token becomes `None`, which suits pages that look different when signed in. |
| `user_auth: &UserAuth` | Required, and the result is cached in the request. Several guards in the same route then verify the token only once. |

Adding the `forward` option is a fourth way: a failing guard hands the request to the next matching route instead of answering `401` itself, which is how one path can serve both an admin page and a "you are not an admin" page.

## Without Rocket

The same type can sign and verify tokens on its own.

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

A key is the only thing which is required: either `key`, or `encoding_key` together with `decoding_key`.

### Keys and algorithm

| Option | Default | Description |
| ------ | ------- | ----------- |
| `key = EXPR` | | The shared secret, only for the `HS*` algorithms. Anything which is `AsRef<[u8]>` works. |
| `encoding_key = EXPR` | | An [`EncodingKey`], needed instead of `key` by the asymmetric algorithms. |
| `decoding_key = EXPR` | | A [`DecodingKey`], needed instead of `key` by the asymmetric algorithms. |
| `algorithm = NAME` | `HS256` | One of `HS256`, `HS384`, `HS512`, `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `EdDSA`. |

### Where the token comes from

Sources are tried in the order they are written. When none is given, `header` is used.

| Option | Description |
| ------ | ----------- |
| `header` | Reads `Authorization: Bearer <token>`. Written as `header(name = "x-auth", scheme = "Token")` to change the header or the scheme. |
| `cookie = "name"` | Reads a cookie. Written as `cookie(name = "…", domain = "…", path = "…", secure = true, http_only = false, same_site = "lax", max_age = false)` to change its attributes. |
| `query = "name"` | Reads a query parameter. |

### What is validated

| Option | Default | Description |
| ------ | ------- | ----------- |
| `leeway = 60` | `60` | The number of seconds of clock skew allowed when `exp` and `nbf` are validated. |
| `reject_expiring_in = 30` | `0` | Rejects a token which expires within this many seconds, so that one cannot run out while it is still travelling. |
| `validate_exp = false` | `true` | Whether `exp` is validated. |
| `validate_nbf = true` | `false` | Whether `nbf` is validated. |
| `validate_aud = false` | `true` | Whether `aud` is validated. |
| `issuer = "…"` | | The accepted `iss` claims. An array accepts several of them. |
| `audience = "…"` | | The accepted `aud` claims. An array accepts several of them. |
| `subject = "…"` | | The accepted `sub` claim. |
| `required_claims = ["exp"]` | `["exp"]` | The claims a token has to carry. |

### Other

| Option | Description |
| ------ | ----------- |
| `realm = "…"` | The realm of the `WWW-Authenticate` challenge. Needs a `header` source. |
| `forward` | Makes a failing guard forward with `401 Unauthorized` instead of answering with it. |

## Things to watch out for

* Claims which carry an `aud` field are rejected unless the guard also has an `audience` option, because that is what RFC 7519 asks for. Set `validate_aud = false` to accept any audience.
* A token in a query parameter ends up in the URL, which proxies and access logs tend to keep. Prefer the header or a cookie whenever there is a choice.
* A browser only accepts `same_site = "none"` when `secure = true` is set as well, so writing `secure = false` next to it is a compile error.
* The `jwt` attribute takes an expression for `key`, `encoding_key` and `decoding_key`, so the key can be read at runtime instead of being written into the source. It is evaluated once, on the first request which needs it.

## Crypto backend

[`jsonwebtoken`] needs exactly one crypto backend, and picks it at runtime from the features which are enabled. This crate turns the pure Rust one on by default; to use AWS-LC instead, turn the default features off.

```toml
[dependencies]
rocket-jwt-authorization = { version = "0.3", default-features = false, features = ["aws_lc_rs", "use_pem"] }
```

Enabling both `rust_crypto` and `aws_lc_rs`, or neither of them, is a compile error.
*/

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
compile_error!("`rust_crypto` and `aws_lc_rs` cannot be enabled together");

#[cfg(not(any(feature = "rust_crypto", feature = "aws_lc_rs")))]
compile_error!("exactly one of `rust_crypto` and `aws_lc_rs` must be enabled");

extern crate self as rocket_jwt_authorization;

mod challenge;
mod cookie;
mod error;
mod fairing;

pub use challenge::{ChallengeConfig, JwtChallenge};
pub use cookie::CookieConfig;
pub use error::JwtGuardError;
pub use fairing::JwtFairing;
pub use jsonwebtoken::{
    self, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors, errors::Error,
};
use rocket::{
    http::{Cookie, CookieJar},
    request::Request,
};
pub use rocket_jwt_authorization_derive::JWT;
use serde::{Serialize, de::DeserializeOwned};

/// The traits, the fairing, and the derive macro which are needed to use a claims struct as a request guard.
pub mod prelude {
    pub use super::{FromJwtRequest, JWT, Jwt, JwtChallenge, JwtCookie, JwtFairing};
}

#[doc(hidden)]
pub mod __private {
    pub use std::sync::OnceLock;

    pub use rocket;

    pub use crate::fairing::{record_challenge, record_cookie_removal};

    /// Reads the token out of a header value like `Bearer abc`. The scheme is matched case-insensitively, as RFC 7235 requires.
    #[inline]
    pub fn scheme_token<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
        let value = value.trim();

        if scheme.is_empty() {
            return Some(value);
        }

        let (found, rest) = value.split_at_checked(scheme.len())?;

        if !found.eq_ignore_ascii_case(scheme) {
            return None;
        }

        Some(rest.strip_prefix(' ')?.trim())
    }
}

/// A set of claims which can be signed into a token and verified back. Implemented by `#[derive(JWT)]`.
pub trait Jwt: Serialize + DeserializeOwned + Sized {
    /// The key which signs a token, built from the `key` or the `encoding_key` option.
    fn jwt_encoding_key() -> &'static EncodingKey;

    /// The key which verifies a token, built from the `key` or the `decoding_key` option.
    fn jwt_decoding_key() -> &'static DecodingKey;

    /// The header written into every token, which carries the algorithm to use.
    fn jwt_header() -> &'static Header;

    /// The rules a token has to satisfy, built from the validation options of the `jwt` attribute.
    fn jwt_validation() -> &'static Validation;

    /// Signs these claims into a token.
    #[inline]
    fn sign(&self) -> Result<String, Error> {
        self.sign_with_header(Self::jwt_header())
    }

    /// Signs these claims under a header of your own, which is how a `kid` reaches a token while keys are being rotated.
    /// The algorithm of the header has to be the one the guard validates, otherwise the token it produces cannot be verified back.
    #[inline]
    fn sign_with_header(&self, header: &Header) -> Result<String, Error> {
        jsonwebtoken::encode(header, self, Self::jwt_encoding_key())
    }

    /// Verifies the signature of a token and validates its claims.
    #[inline]
    fn verify<T: AsRef<[u8]>>(token: T) -> Result<Self, Error> {
        Self::verify_with_header(token).map(|token_data| token_data.claims)
    }

    /// Verifies a token and keeps its header, which is where a `kid` can be read from.
    #[inline]
    fn verify_with_header<T: AsRef<[u8]>>(token: T) -> Result<TokenData<Self>, Error> {
        jsonwebtoken::decode::<Self>(token, Self::jwt_decoding_key(), Self::jwt_validation())
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
    /// The attributes of the cookie, built from the `cookie` source of the `jwt` attribute.
    fn jwt_cookie_config() -> &'static CookieConfig;

    /// Signs these claims into a cookie without adding it to a jar.
    #[inline]
    fn to_cookie(&self) -> Result<Cookie<'static>, Error> {
        Ok(Self::jwt_cookie_config().build_cookie(self.sign()?, self.expiration()))
    }

    /// Signs these claims and adds the cookie to a jar, which is how a login route hands out a token.
    #[inline]
    fn add_cookie(&self, cookies: &CookieJar<'_>) -> Result<(), Error> {
        cookies.add(self.to_cookie()?);

        Ok(())
    }

    /// Tells the browser to drop the cookie, which is how a logout route ends a session.
    #[inline]
    fn remove_cookie(cookies: &CookieJar<'_>) {
        cookies.remove(Self::jwt_cookie_config().build_removal_cookie());
    }
}
