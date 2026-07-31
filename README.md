`jwt-authorization` Request Guard for Rocket Framework
====================

[![CI](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml)

Turn a claims struct into a Rocket request guard.

`#[derive(JWT)]` writes the code which pulls a JSON Web Token out of a request, checks its signature, and validates its claims. A route which asks for the struct runs only after all of that has succeeded, so a handler never has to deal with an unauthenticated request.

```rust
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY)]
struct UserAuth {
    exp: u64,
    id: i32,
}

// Without a valid token this function is never called.
#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}
```

## Crates in this repository

| Crate | Description |
| ----- | ----------- |
| [rocket-jwt-authorization](rocket-jwt-authorization/README.md) | The crate to depend on. It holds the traits, the cookie configuration, and re-exports the derive macro. |
| [rocket-jwt-authorization-derive](rocket-jwt-authorization-derive/README.md) | The `JWT` derive macro on its own. It is pulled in automatically, so there is no reason to depend on it directly. |

Start with the [rocket-jwt-authorization README](rocket-jwt-authorization/README.md). It covers the whole `jwt` attribute and links to a runnable example for each feature.

## Crates.io

https://crates.io/crates/rocket-jwt-authorization

## Documentation

https://docs.rs/rocket-jwt-authorization

## License

[MIT](LICENSE)
