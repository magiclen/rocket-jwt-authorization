//! A browser login session built on a cookie, without any template engine.
//!
//! Run it and open <http://127.0.0.1:8000> in a browser, then visit `/login` and `/logout` to watch the home page change.

use rocket::{get, http::CookieJar, launch, routes};
use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

// Read this from the environment in a real application, and never commit it.
static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

/// Adding a `cookie` source also gives this type the `JwtCookie` trait, which is where `add_cookie` comes from.
#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, cookie = "access_token")]
struct UserAuth {
    exp: u64,
    id:  i32,
}

/// The cookie is `HttpOnly` and `SameSite=Strict` by default, and its `Max-Age` follows the `exp` claim.
#[get("/login")]
fn login(cookies: &CookieJar) -> &'static str {
    let user_auth = UserAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600, id: 1
    };

    user_auth.add_cookie(cookies).unwrap();

    "Logged in. Go back to the home page."
}

#[get("/logout")]
fn logout(cookies: &CookieJar) -> &'static str {
    UserAuth::remove_cookie(cookies);

    "Logged out. Go back to the home page."
}

/// `Option<UserAuth>` never fails, so a visitor without a token gets a normal page instead of a 401.
#[get("/")]
fn index(user_auth: Option<UserAuth>) -> String {
    match user_auth {
        Some(user_auth) => format!("Logged in user id = {}. Visit /logout to leave.", user_auth.id),
        None => "Not logged in. Visit /login to get a cookie.".to_string(),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, login, logout])
}
