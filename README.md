`jwt-authorization` Request Guard for Rocket Framework
====================

[![CI](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml)

This crate provides a procedural macro to create request guards used for authorization.

Deriving `JWT` turns a claims struct into a Rocket request guard which reads a JSON Web Token from a request, verifies its signature, and validates its claims (`exp` by default).

## Example

```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rocket::{get, http::CookieJar, routes};
use rocket_jwt_authorization::prelude::*;
use serde::{Deserialize, Serialize};

static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, header, cookie = "access_token")]
struct UserAuth {
    exp: u64,
    id: i32,
}

#[get("/login")]
fn login(cookies: &CookieJar) -> &'static str {
    let user_auth = UserAuth {
        exp: (SystemTime::now() + Duration::from_secs(3600))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        id: 1,
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
    id: i32,
}

let user_auth = UserAuth {
    exp: jsonwebtoken::get_current_timestamp() + 3600,
    id: 1,
};

let token = user_auth.sign().unwrap();

assert_eq!(user_auth, UserAuth::verify(token).unwrap());
```

## Options of the `jwt` attribute

| Option | Default | Description |
| ------ | ------- | ----------- |
| `key = EXPR` | | The shared secret, only for the `HS*` algorithms. Anything which is `AsRef<[u8]>` works. |
| `encoding_key = EXPR` | | An `EncodingKey`, needed instead of `key` by the asymmetric algorithms. |
| `decoding_key = EXPR` | | A `DecodingKey`, needed instead of `key` by the asymmetric algorithms. |
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

[jsonwebtoken](https://crates.io/crates/jsonwebtoken) needs exactly one crypto backend. This crate enables the pure Rust one by default; to use AWS-LC instead, turn the default features off.

```toml
[dependencies]
rocket-jwt-authorization = { version = "0.3", default-features = false, features = ["aws_lc_rs", "use_pem"] }
```

## Crates.io

https://crates.io/crates/rocket-jwt-authorization

## Documentation

https://docs.rs/rocket-jwt-authorization

## License

[MIT](LICENSE)
