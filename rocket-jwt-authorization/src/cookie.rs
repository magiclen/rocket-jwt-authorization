use std::borrow::Cow;

use rocket::{
    http::{Cookie, SameSite},
    time::Duration,
};

/// The attributes of the cookie which carries a token.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    name:      Cow<'static, str>,
    domain:    Option<Cow<'static, str>>,
    path:      Option<Cow<'static, str>>,
    secure:    Option<bool>,
    http_only: bool,
    same_site: Option<SameSite>,
    max_age:   bool,
}

impl CookieConfig {
    /// Creates a config whose cookie is `HttpOnly`, `SameSite=Strict`, `Path=/`, and expires together with the `exp` claim.
    #[inline]
    pub fn new<N: Into<Cow<'static, str>>>(name: N) -> Self {
        CookieConfig {
            name:      name.into(),
            domain:    None,
            path:      Some(Cow::Borrowed("/")),
            secure:    None,
            http_only: true,
            same_site: Some(SameSite::Strict),
            max_age:   true,
        }
    }

    /// Sets `Domain`, which is only needed to share the cookie with subdomains. Without it the cookie is sent back to the exact host which set it.
    #[inline]
    pub fn domain<D: Into<Cow<'static, str>>>(mut self, domain: D) -> Self {
        self.domain = Some(domain.into());

        self
    }

    /// Sets `Path`, which limits the cookie to a part of the site. It defaults to `/`.
    #[inline]
    pub fn path<P: Into<Cow<'static, str>>>(mut self, path: P) -> Self {
        self.path = Some(path.into());

        self
    }

    /// Rocket already sets `Secure` when it serves over TLS, so this is only needed to force the attribute.
    #[inline]
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = Some(secure);

        self
    }

    /// Sets `HttpOnly`, which hides the cookie from JavaScript. It is on by default.
    #[inline]
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;

        self
    }

    /// Sets `SameSite`, which decides whether the cookie travels with cross-site requests. It defaults to `Strict`.
    /// A browser only accepts `SameSite=None` when `Secure` is set as well.
    #[inline]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);

        self
    }

    /// Whether `Max-Age` is set from the `exp` claim. When it is off, the cookie is a session cookie.
    #[inline]
    pub fn max_age(mut self, max_age: bool) -> Self {
        self.max_age = max_age;

        self
    }

    /// The name of the cookie which carries the token.
    #[inline]
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub(crate) fn build_cookie(&self, token: String, expiration: Option<u64>) -> Cookie<'static> {
        let mut cookie = Cookie::new(self.name.clone(), token);

        if let Some(domain) = self.domain.as_ref() {
            cookie.set_domain(domain.clone());
        }

        if let Some(path) = self.path.as_ref() {
            cookie.set_path(path.clone());
        }

        if let Some(secure) = self.secure {
            cookie.set_secure(secure);
        }

        cookie.set_http_only(self.http_only);

        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }

        if self.max_age
            && let Some(expiration) = expiration
        {
            let seconds = expiration.saturating_sub(jsonwebtoken::get_current_timestamp());

            cookie.set_max_age(Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX)));
        }

        cookie
    }

    /// `Domain` and `Path` have to be the same as the ones used when the cookie was added, otherwise the browser keeps it.
    pub(crate) fn build_removal_cookie(&self) -> Cookie<'static> {
        let mut cookie = Cookie::from(self.name.clone());

        if let Some(domain) = self.domain.as_ref() {
            cookie.set_domain(domain.clone());
        }

        if let Some(path) = self.path.as_ref() {
            cookie.set_path(path.clone());
        }

        cookie
    }
}
