//! The smallest thing this crate can do: protect a route with an `Authorization: Bearer` token.
//!
//! Run it, then try:
//!
//! ```bash
//! curl -i http://127.0.0.1:8000/            # 401, the route never runs
//! TOKEN=$(curl -s http://127.0.0.1:8000/login)
//! curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/
//! ```

use rocket::{get, launch, routes};
use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

// Read this from the environment in a real application, and never commit it.
static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

/// The claims of the token. `exp` is validated on every request, so an expired token cannot get in.
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY)]
struct UserAuth {
    exp: u64,
    id:  i32,
}

/// Pretend the user just typed a correct password, and hand out a token which is good for an hour.
#[get("/login")]
fn login() -> String {
    let user_auth = UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600, id: 1
    };

    user_auth.sign().unwrap()
}

/// `UserAuth` here is a request guard. Rocket only calls this function once the token has been verified.
#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, login])
}
