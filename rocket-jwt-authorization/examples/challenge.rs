//! Answering a rejected request with the `WWW-Authenticate` challenge which RFC 7235 asks every `401` to carry.
//!
//! Rocket hands a request whose guard failed to a catcher, and a catcher knows nothing about the guard,
//! so the challenge only reaches the client once `JwtFairing` is attached.
//!
//! Run it, then try:
//!
//! ```bash
//! curl -i http://127.0.0.1:8000/            # no token at all
//! TOKEN=$(curl -s http://127.0.0.1:8000/short-lived)
//! sleep 3
//! curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/   # expired
//! curl -i -H "Authorization: Bearer nonsense" http://127.0.0.1:8000/ # not even a token
//! ```

use rocket::{get, launch, routes};
use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

// Read this from the environment in a real application, and never commit it.
static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

/// `realm` names the set of resources this token opens, and ends up in every challenge this guard sends back.
///
/// `leeway` is only zero so that the token below really is refused a few seconds later.
/// Leave it at its default of 60 in a real application, where the clocks of two machines are never quite the same.
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, realm = "api", leeway = 0)]
struct UserAuth {
    exp: u64,
    id:  i32,
}

/// The token is good for two seconds, which is long enough to copy and short enough to watch expire.
#[get("/short-lived")]
fn short_lived() -> String {
    UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 2, id: 1
    }
    .sign()
    .unwrap()
}

/// A request without a valid token never reaches this function.
///
/// | Request | `WWW-Authenticate` |
/// | ------- | ------------------ |
/// | no token | `Bearer realm="api"` |
/// | expired token | `Bearer realm="api", error="invalid_token", error_description="the token has expired"` |
/// | garbage token | `Bearer realm="api", error="invalid_token", error_description="the token is malformed"` |
#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}

#[launch]
fn rocket() -> _ {
    // Without this fairing every answer above is a bare 401 with no challenge.
    rocket::build().attach(JwtFairing).mount("/", routes![index, short_lived])
}
