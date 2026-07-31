`jwt-authorization` Request Guard for Rocket Framework
====================

[![CI](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml)

Turn a claims struct into a Rocket request guard.

`#[derive(JWT)]` writes the code which pulls a JSON Web Token out of a request, checks its signature, and validates its claims. A route which asks for the struct runs only after all of that has succeeded, so a handler never has to deal with an unauthenticated request. Anything else gets `401 Unauthorized` before the handler is reached.

## Getting started

Add two things to a struct: the `serde` derives, so the claims can be turned into JSON, and `JWT` with a `jwt` attribute which says how tokens are signed and where they come from.

```rust
use rocket::{get, launch, routes};
use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

// Read this from the environment in a real application, and never commit it.
static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY)]
struct UserAuth {
    exp: u64,
    id: i32,
}

#[get("/login")]
fn login() -> String {
    let user_auth = UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600,
        id: 1,
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

Adding a `cookie` source also gives the type the `JwtCookie` trait, which knows how to write and clear the cookie.

```rust
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, cookie = "access_token")]
struct UserAuth {
    exp: u64,
    id: i32,
}

#[get("/login")]
fn login(cookies: &CookieJar) -> &'static str {
    let user_auth = UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600,
        id: 1,
    };

    user_auth.add_cookie(cookies).unwrap();

    "Logged in."
}

#[get("/logout")]
fn logout(cookies: &CookieJar) -> &'static str {
    UserAuth::remove_cookie(cookies);

    "Logged out."
}
```

The cookie is `HttpOnly`, `SameSite=Strict` and `Path=/`, and its `Max-Age` follows the `exp` claim, so it disappears from the browser when the token stops being valid. Use `cookie(...)` instead of `cookie = "…"` to change any of that.

When a cookie holds a token which cannot be verified, the guard also clears the cookie, because the browser would otherwise keep sending a token which is never going to work again.

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

A key is the only thing which is required: either `key`, or `encoding_key` together with `decoding_key`.

### Keys and algorithm

| Option | Default | Description |
| ------ | ------- | ----------- |
| `key = EXPR` | | The shared secret, only for the `HS*` algorithms. Anything which is `AsRef<[u8]>` works. |
| `encoding_key = EXPR` | | An `EncodingKey`, needed instead of `key` by the asymmetric algorithms. |
| `decoding_key = EXPR` | | A `DecodingKey`, needed instead of `key` by the asymmetric algorithms. |
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
| `forward` | Makes a failing guard forward with `401 Unauthorized` instead of answering with it. |

## Things to watch out for

* Claims which carry an `aud` field are rejected unless the guard also has an `audience` option, because that is what RFC 7519 asks for. Set `validate_aud = false` to accept any audience.
* A token in a query parameter ends up in the URL, which proxies and access logs tend to keep. Prefer the header or a cookie whenever there is a choice.
* A browser only accepts `same_site = "none"` when `secure = true` is set as well.
* The `jwt` attribute takes an expression for `key`, `encoding_key` and `decoding_key`, so the key can be read at runtime instead of being written into the source. It is evaluated once, on the first request which needs it.

## Crypto backend

[jsonwebtoken](https://crates.io/crates/jsonwebtoken) needs exactly one crypto backend, and picks it at runtime from the features which are enabled. This crate turns the pure Rust one on by default; to use AWS-LC instead, turn the default features off.

```toml
[dependencies]
rocket-jwt-authorization = { version = "0.3", default-features = false, features = ["aws_lc_rs", "use_pem"] }
```

Enabling both `rust_crypto` and `aws_lc_rs`, or neither of them, still compiles, but signing and verifying then panic at runtime.

## Crates.io

https://crates.io/crates/rocket-jwt-authorization

## Documentation

https://docs.rs/rocket-jwt-authorization

## License

[MIT](LICENSE)
