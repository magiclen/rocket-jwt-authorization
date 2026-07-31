//! Signing with an asymmetric algorithm, where the private key signs and the public key verifies.
//!
//! `key` only works with the `HS*` algorithms, so `ES256` needs an `encoding_key` and a `decoding_key` instead.
//! The service which hands out tokens is then the only one which needs the private key.
//!
//! The key pair in `examples/keys` was generated for this example alone.
//! It is public, so never use it for anything real.
//!
//! Run it, then try:
//!
//! ```bash
//! TOKEN=$(curl -s http://127.0.0.1:8000/login)
//! curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/
//! ```

use rocket::{get, launch, routes};
use rocket_jwt_authorization::{DecodingKey, EncodingKey, jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

static PRIVATE_KEY: &str = include_str!("keys/es256-private.pem");
static PUBLIC_KEY: &str = include_str!("keys/es256-public.pem");

/// Both keys are built once and then reused, so the PEM parsing here only happens on the first request.
#[derive(Serialize, Deserialize, JWT)]
#[jwt(
    algorithm = ES256,
    encoding_key = EncodingKey::from_ec_pem(PRIVATE_KEY.as_bytes()).unwrap(),
    decoding_key = DecodingKey::from_ec_pem(PUBLIC_KEY.as_bytes()).unwrap(),
)]
struct UserAuth {
    exp: u64,
    id:  i32,
}

#[get("/login")]
fn login() -> String {
    UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600, id: 1
    }
    .sign()
    .unwrap()
}

#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, login])
}
