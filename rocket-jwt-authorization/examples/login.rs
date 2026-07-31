#[macro_use]
extern crate rocket_include_tera;

#[macro_use]
extern crate rocket;

use std::{
    collections::HashMap,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rocket::{
    State,
    form::{self, Form},
    http::CookieJar,
    response::Redirect,
};
use rocket_include_tera::{EtagIfNoneMatch, TeraContextManager, TeraResponse};
use rocket_jwt_authorization::prelude::*;
use serde::{Deserialize, Serialize};
use validators::prelude::*;
use validators_prelude::regex::Regex;

static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

static RE_USERNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\w{1,30}$").unwrap());
static RE_PASSWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\S ]{8,}$").unwrap());

#[derive(Debug, Clone, Validator)]
#[validator(regex(regex = RE_USERNAME))]
pub struct Username(String);

#[derive(Debug, Clone, Validator)]
#[validator(regex(regex = RE_PASSWORD))]
pub struct Password(String);

#[derive(Debug, FromForm)]
struct LoginModel<'v> {
    username: form::Result<'v, Username>,
    password: form::Result<'v, Password>,
}

#[derive(Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, cookie = "access_token", header, query = "access_token")]
pub struct UserAuth {
    exp: u64,
    id:  i32,
}

#[post("/login", data = "<model>")]
fn login_post(
    cm: &State<TeraContextManager>,
    etag_if_none_match: &EtagIfNoneMatch,
    model: Form<LoginModel>,
    cookies: &CookieJar,
) -> Result<Redirect, TeraResponse> {
    let mut map = HashMap::new();

    UserAuth::remove_cookie(cookies);

    match model.username.as_ref() {
        Ok(username) => match model.password.as_ref() {
            Ok(password) => {
                if username.0 == "magiclen" && password.0 == "12345678" {
                    let user_auth = UserAuth {
                        exp: (SystemTime::now() + Duration::from_secs(10))
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        id:  1,
                    };

                    user_auth.add_cookie(cookies).unwrap();

                    map.insert(
                        "message",
                        "Login successfully, a cookie has been written. Open home page to see the \
                         result.",
                    );
                } else {
                    map.insert("message", "Invalid username or password.");
                }
            },
            Err(_) => {
                map.insert("message", "The format of your password is incorrect.");
            },
        },
        Err(_) => {
            map.insert("message", "The format of your username is incorrect.");
        },
    }

    Err(tera_response!(cm, etag_if_none_match, "login", &map))
}

#[get("/login")]
fn login_get(cm: &State<TeraContextManager>, etag_if_none_match: &EtagIfNoneMatch) -> TeraResponse {
    tera_response_cache!(cm, etag_if_none_match, "login", {
        println!("Generate login and cache it...");

        tera_response!(cm, EtagIfNoneMatch::default(), "login")
    })
}

#[allow(clippy::result_large_err)] // TODO should use `Box` after a newer Rocket is released
#[get("/")]
fn index(user_auth: Option<UserAuth>) -> Result<String, Redirect> {
    // An expired token is rejected by the request guard, which also drops the cookie carrying it.
    match user_auth {
        Some(user_auth) => Ok(format!("Logged in user id = {}", user_auth.id)),
        None => Err(Redirect::temporary(uri!(login_get))),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(tera_resources_initializer!("login" => "examples/views/login.tera"))
        .mount("/", routes![index])
        .mount("/", routes![login_get, login_post])
}
