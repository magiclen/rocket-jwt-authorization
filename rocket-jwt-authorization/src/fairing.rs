use std::sync::{Mutex, PoisonError};

use rocket::{
    Request, Response,
    fairing::{Fairing, Info, Kind},
    http::{Header, SameSite, Status},
};

use crate::{ChallengeConfig, CookieConfig, JwtGuardError, challenge::error_description};

/// What a failed guard wants its challenge to say, held as references so that a request which never answers with one pays for nothing.
struct RecordedChallenge(Mutex<Option<(&'static ChallengeConfig, Option<&'static str>)>>);

/// The cookies failed guards wanted the browser to drop.
struct RecordedRemovals(Mutex<Vec<&'static CookieConfig>>);

/// Remembers the challenge of a guard which just failed. Called by the code which `#[derive(JWT)]` writes.
#[doc(hidden)]
#[inline]
pub fn record_challenge(
    request: &Request<'_>,
    config: &'static ChallengeConfig,
    error: &JwtGuardError,
) {
    // RFC 6750 asks a challenge to carry no error code when the request simply came without credentials.
    let description = match error {
        JwtGuardError::Missing => None,
        JwtGuardError::Invalid(error) => Some(error_description(error)),
    };

    let recorded = request.local_cache(|| RecordedChallenge(Mutex::new(None)));

    *recorded.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((config, description));
}

/// Remembers the cookie a guard which just failed wants dropped. Called by the code which `#[derive(JWT)]` writes.
#[doc(hidden)]
#[inline]
pub fn record_cookie_removal(request: &Request<'_>, config: &'static CookieConfig) {
    let recorded = request.local_cache(|| RecordedRemovals(Mutex::new(Vec::new())));
    let mut configs = recorded.0.lock().unwrap_or_else(PoisonError::into_inner);

    if !configs.iter().any(|recorded| std::ptr::eq(*recorded, config)) {
        configs.push(config);
    }
}

/// Writes back onto a `401 Unauthorized` answer what Rocket drops when a request guard fails.
///
/// A guard which fails hands the request to a catcher, and a catcher knows nothing about the guard, so two things are lost on the way:
///
/// * The `WWW-Authenticate` challenge which RFC 7235 asks every `401` to carry.
/// * The removal of a cookie which held a token that could not be verified, because Rocket resets the cookie changes of a failed request before it runs a catcher.
///
/// Attaching this fairing puts both back. Without it a `401` carries no challenge, and an invalid token stays in the browser until the request reaches a route which answers normally.
///
/// ```rust,no_run
/// # use rocket::{get, launch, routes};
/// # use rocket_jwt_authorization::{jsonwebtoken, prelude::*};
/// # use serde::{Deserialize, Serialize};
/// # static SECRET_KEY: &str = "cc818bd5-6d16-4a67-b109-43d22d252f88";
/// # #[derive(Serialize, Deserialize, JWT)]
/// # #[jwt(key = SECRET_KEY, realm = "api")]
/// # struct UserAuth {
/// #     exp: u64,
/// #     id:  i32,
/// # }
/// # #[get("/")]
/// # fn index(user_auth: UserAuth) -> String { user_auth.id.to_string() }
/// #[launch]
/// fn rocket() -> _ {
///     rocket::build().attach(JwtFairing).mount("/", routes![index])
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct JwtFairing;

#[rocket::async_trait]
impl Fairing for JwtFairing {
    #[inline]
    fn info(&self) -> Info {
        Info {
            name: "JWT", kind: Kind::Response
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if response.status() != Status::Unauthorized {
            return;
        }

        let recorded_challenge = request.local_cache(|| RecordedChallenge(Mutex::new(None)));
        let challenge = *recorded_challenge.0.lock().unwrap_or_else(PoisonError::into_inner);

        if let Some((config, description)) = challenge
            && !response.headers().contains("WWW-Authenticate")
            && let Some(value) = config.header_value(description)
        {
            response.set_header(Header::new("WWW-Authenticate", value));
        }

        let recorded_removals = request.local_cache(|| RecordedRemovals(Mutex::new(Vec::new())));
        let configs = recorded_removals.0.lock().unwrap_or_else(PoisonError::into_inner);

        for config in configs.iter() {
            let mut cookie = config.build_removal_cookie();

            // The defaults `CookieJar::remove` applies, so that the browser matches this against the cookie it holds.
            if cookie.path().is_none() {
                cookie.set_path("/");
            }

            if cookie.same_site().is_none() {
                cookie.set_same_site(SameSite::Lax);
            }

            cookie.make_removal();

            response.adjoin_header(cookie);
        }
    }
}
