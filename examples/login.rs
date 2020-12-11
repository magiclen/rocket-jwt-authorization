#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket_include_tera;

#[macro_use]
extern crate validators_derive;

extern crate validators;

extern crate once_cell;

#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_jwt_authorization;

extern crate serde;

#[macro_use]
extern crate serde_derive;

extern crate hmac;
extern crate jwt;
extern crate sha2;

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jwt::RegisteredClaims;

use rocket::http::Cookies;
use rocket::request::Form;
use rocket::response::Redirect;
use rocket::State;

use rocket_include_tera::{TeraContextManager, TeraResponse};

use validators::prelude::*;
use validators::RegexError;
use validators_prelude::regex::Regex;

use once_cell::sync::Lazy;

static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

static RE_USERNAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\w{1,30}$").unwrap());
static RE_PASSWORD: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[\S ]{8,}$").unwrap());

#[derive(Debug, Clone, Validator)]
#[validator(regex(RE_USERNAME))]
pub struct Username(String);

#[derive(Debug, Clone, Validator)]
#[validator(regex(RE_PASSWORD))]
pub struct Password(String);

#[derive(Debug, FromForm)]
struct LoginModel {
    username: Result<Username, RegexError>,
    password: Result<Password, RegexError>,
}

#[derive(Serialize, Deserialize, JWT)]
#[jwt(SECRET_KEY, sha2::Sha256, Cookie = "access_token")]
pub struct UserAuth {
    #[serde(flatten)]
    registered: RegisteredClaims,
    id: i32,
}

#[post("/login", data = "<model>")]
fn login_post(model: Form<LoginModel>, mut cookies: Cookies) -> Result<Redirect, TeraResponse> {
    let mut map = HashMap::new();

    UserAuth::remove_cookie(&mut cookies);

    match model.username.as_ref() {
        Ok(username) => {
            match model.password.as_ref() {
                Ok(password) => {
                    if username.0 == "magiclen" && password.0 == "12345678" {
                        let registered = RegisteredClaims {
                            expiration: Some(
                                (SystemTime::now() + Duration::from_secs(10))
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            ),
                            ..RegisteredClaims::default()
                        };

                        let user_auth = UserAuth {
                            registered,
                            id: 1,
                        };

                        user_auth.set_cookie(&mut cookies);

                        map.insert(
                            "message",
                            "Login successfully, a cookie has been written. Open home page to see the result.",
                        );
                    } else {
                        map.insert("message", "Invalid username or password.");
                    }
                }
                Err(_) => {
                    map.insert("message", "The format of your password is incorrect.");
                }
            }
        }
        Err(_) => {
            map.insert("message", "The format of your username is incorrect.");
        }
    }

    Err(tera_response!("login", &map))
}

#[get("/login")]
fn login_get(cm: State<TeraContextManager>) -> TeraResponse {
    tera_response_cache!(cm, "login", {
        println!("Generate login and cache it...");

        tera_response!("login")
    })
}

#[get("/")]
fn index(user_auth: Option<UserAuth>, mut cookies: Cookies) -> Result<String, Redirect> {
    match user_auth {
        Some(user_auth) => {
            if SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                > user_auth.registered.expiration.unwrap()
            {
                UserAuth::remove_cookie(&mut cookies);

                Ok(String::from("Login token expired, please log in again!"))
            } else {
                Ok(format!("Logged in user id = {}", user_auth.id))
            }
        }
        None => Err(Redirect::temporary(uri!(login_get))),
    }
}

fn main() {
    rocket::ignite()
        .attach(TeraResponse::fairing(|tera| {
            tera_resources_initialize!(tera, "login", "examples/views/login.tera",);
        }))
        .mount("/", routes![index])
        .mount("/", routes![login_get, login_post])
        .launch();
}
