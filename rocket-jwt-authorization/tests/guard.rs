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

/// A token whose `aud` claim is not checked, which needs `validate_aud` because `jsonwebtoken` validates it by default.
#[derive(Debug, PartialEq, Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, validate_aud = false)]
struct AnyAudienceAuth {
    exp: u64,
    aud: String,
    id:  i32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, JWT)]
#[jwt(key = SECRET_KEY, cookie(name = "shared_token", domain = "example.com"))]
struct SharedAuth {
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

#[get("/any-audience")]
fn any_audience(auth: AnyAudienceAuth) -> String {
    auth.id.to_string()
}

#[get("/shared-login")]
fn shared_login(cookies: &CookieJar) -> &'static str {
    SharedAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600, id: 1
    }
    .add_cookie(cookies)
    .unwrap();

    "Logged in."
}

fn user_auth(expires_in: i64) -> UserAuth {
    UserAuth {
        exp: jsonwebtoken::get_current_timestamp().saturating_add_signed(expires_in),
        id:  1,
    }
}

fn client() -> Client {
    Client::tracked(Rocket::build().mount("/", routes![index, login, any_audience, shared_login]))
        .unwrap()
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

#[test]
fn cookie_domain_is_set() {
    let client = client();

    let response = client.get("/shared-login").dispatch();

    let cookie = response.cookies().get("shared_token").unwrap();

    assert_eq!(Some("example.com"), cookie.domain());
}

#[test]
fn audience_is_not_validated_when_turned_off() {
    let client = client();

    let auth = AnyAudienceAuth {
        exp: jsonwebtoken::get_current_timestamp() + 3600,
        aud: "somebody-else".to_string(),
        id:  1,
    };

    let token = auth.sign().unwrap();

    let response = client.get("/any-audience").header(bearer(token.as_str())).dispatch();

    assert_eq!(Status::Ok, response.status());
    assert_eq!("1", response.into_string().unwrap());
}
