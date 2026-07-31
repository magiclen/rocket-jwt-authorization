//! The four ways a derived guard can appear in a route: `UserAuth`, `Option<UserAuth>`, `&UserAuth`, and a guard which forwards.
//!
//! Run it, then try:
//!
//! ```bash
//! USER=$(curl -s http://127.0.0.1:8000/login)
//! ADMIN=$(curl -s http://127.0.0.1:8000/admin-login)
//!
//! curl -s http://127.0.0.1:8000/maybe                             # works without a token
//! curl -s -H "Authorization: Bearer $USER"  http://127.0.0.1:8000/twice
//! curl -s -H "Authorization: Bearer $USER"  http://127.0.0.1:8000/admin  # falls through
//! curl -s -H "Authorization: Bearer $ADMIN" http://127.0.0.1:8000/admin
//! ```

use rocket::{get, launch, routes};
use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

// Read these from the environment in a real application, and never commit them.
static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";
static ADMIN_SECRET_KEY: &str = "3a0c0c1e-1f4a-4a0b-9a2e-9e1a5a2b6c7d";

#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY)]
struct UserAuth {
    exp: u64,
    id:  i32,
}

/// `forward` makes a failing guard hand the request to the next route instead of answering with 401.
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = ADMIN_SECRET_KEY, forward)]
struct AdminAuth {
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

#[get("/admin-login")]
fn admin_login() -> String {
    AdminAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600, id: 9
    }
    .sign()
    .unwrap()
}

/// The plain type is required. Without a valid token the request stops here with 401.
#[get("/")]
fn index(user_auth: UserAuth) -> String {
    format!("Logged in user id = {}", user_auth.id)
}

/// `Option<T>` turns a missing or broken token into `None` rather than an error.
#[get("/maybe")]
fn maybe(user_auth: Option<UserAuth>) -> String {
    match user_auth {
        Some(user_auth) => format!("Logged in user id = {}", user_auth.id),
        None => "Anonymous visitor".to_string(),
    }
}

/// `&T` reads the result out of the request cache, so the token is verified once no matter how many guards ask for it.
#[get("/twice")]
fn twice(first: &UserAuth, second: &UserAuth) -> String {
    format!("The same claims twice, verified once: {} and {}", first.id, second.id)
}

/// Tried first. A request without a valid admin token forwards to the route below.
#[get("/admin", rank = 1)]
fn admin_area(admin_auth: AdminAuth) -> String {
    format!("Welcome, admin {}", admin_auth.id)
}

/// Reached whenever `AdminAuth` forwards, which lets the site answer nicely instead of returning a bare 401.
#[get("/admin", rank = 2)]
fn admin_denied() -> &'static str {
    "You need an admin token to see this page."
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![
        index,
        maybe,
        twice,
        login,
        admin_login,
        admin_area,
        admin_denied
    ])
}
