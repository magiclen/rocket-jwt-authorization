use rocket::{
    Rocket, get,
    http::{Cookie, CookieJar, Header, SameSite, Status},
    local::blocking::Client,
    routes,
};
use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
use serde::{Deserialize, Serialize};

static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";

#[derive(Debug, PartialEq, Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, header, cookie = "access_token", query = "access_token")]
struct UserAuth {
    exp: u64,
    id:  i32,
}

#[get("/")]
fn index(user_auth: UserAuth) -> String {
    user_auth.id.to_string()
}

#[get("/login")]
fn login(cookies: &CookieJar) -> &'static str {
    user_auth(3600).add_cookie(cookies).unwrap();

    "Logged in."
}

fn user_auth(expires_in: i64) -> UserAuth {
    UserAuth {
        exp: jsonwebtoken::get_current_timestamp().saturating_add_signed(expires_in),
        id:  1,
    }
}

fn client() -> Client {
    Client::tracked(Rocket::build().mount("/", routes![index, login])).unwrap()
}

fn bearer(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {token}"))
}

#[test]
fn sign_and_verify() {
    let user_auth = user_auth(3600);

    let token = user_auth.sign().unwrap();

    assert_eq!(user_auth, UserAuth::verify(token).unwrap());
}

#[test]
fn authorization_header() {
    let client = client();

    let token = user_auth(3600).sign().unwrap();

    let response = client.get("/").header(bearer(token.as_str())).dispatch();

    assert_eq!(Status::Ok, response.status());
    assert_eq!("1", response.into_string().unwrap());
}

#[test]
fn authorization_header_scheme_is_case_insensitive() {
    let client = client();

    let token = user_auth(3600).sign().unwrap();

    let response =
        client.get("/").header(Header::new("Authorization", format!("bearer {token}"))).dispatch();

    assert_eq!(Status::Ok, response.status());
}

#[test]
fn cookie() {
    let client = client();

    let token = user_auth(3600).sign().unwrap();

    let response = client.get("/").cookie(Cookie::new("access_token", token)).dispatch();

    assert_eq!(Status::Ok, response.status());
    assert_eq!("1", response.into_string().unwrap());
}

#[test]
fn query() {
    let client = client();

    let token = user_auth(3600).sign().unwrap();

    let response = client.get(format!("/?access_token={token}")).dispatch();

    assert_eq!(Status::Ok, response.status());
    assert_eq!("1", response.into_string().unwrap());
}

#[test]
fn expired_token_is_rejected() {
    let client = client();

    let token = user_auth(-3600).sign().unwrap();

    let response = client.get("/").header(bearer(token.as_str())).dispatch();

    assert_eq!(Status::Unauthorized, response.status());
}

#[test]
fn missing_token_is_rejected() {
    let client = client();

    let response = client.get("/").dispatch();

    assert_eq!(Status::Unauthorized, response.status());
}

#[test]
fn added_cookie_is_protected() {
    let client = client();

    let response = client.get("/login").dispatch();

    let cookie = response.cookies().get("access_token").unwrap();

    assert_eq!(Some(true), cookie.http_only());
    assert_eq!(Some(SameSite::Strict), cookie.same_site());
    assert_eq!(Some("/"), cookie.path());
    assert!(cookie.max_age().is_some());

    assert_eq!(1, UserAuth::verify(cookie.value()).unwrap().id);
}
