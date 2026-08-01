use proc_macro2::Span;
use syn::{
    Attribute, Error, Expr, ExprLit, Ident, Lit, LitBool, LitInt, LitStr, Meta, Token,
    punctuated::Punctuated, spanned::Spanned,
};

/// The names of the `jsonwebtoken::Algorithm` variants, used to reject typos at compile time.
const ALGORITHMS: [&str; 12] = [
    "HS256", "HS384", "HS512", "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384",
    "PS512", "EdDSA",
];

/// The key material used for signing and verifying.
pub(crate) enum Key {
    /// A shared secret, only usable with the `HS*` algorithms.
    Secret(Expr),
    /// A separate `EncodingKey` and `DecodingKey`, usable with every algorithm.
    Pair { encoding: Expr, decoding: Expr },
}

/// Where a token can be read from in a request. Sources are tried in the order they are written in the attribute.
pub(crate) enum Source {
    Header { name: Option<Expr>, scheme: Option<Expr> },
    Cookie(Box<CookieOptions>),
    Query { name: Expr },
}

impl Source {
    #[inline]
    const fn as_str(&self) -> &'static str {
        match self {
            Source::Header {
                ..
            } => "header",
            Source::Cookie(_) => "cookie",
            Source::Query {
                ..
            } => "query",
        }
    }
}

pub(crate) struct CookieOptions {
    pub(crate) name:      Expr,
    pub(crate) domain:    Option<Expr>,
    pub(crate) path:      Option<Expr>,
    pub(crate) secure:    Option<LitBool>,
    pub(crate) http_only: Option<LitBool>,
    pub(crate) same_site: Option<Ident>,
    pub(crate) max_age:   Option<LitBool>,
}

pub(crate) struct JwtAttribute {
    pub(crate) key:                Key,
    pub(crate) algorithm:          Ident,
    pub(crate) sources:            Vec<Source>,
    pub(crate) realm:              Option<Expr>,
    pub(crate) leeway:             Option<LitInt>,
    pub(crate) reject_expiring_in: Option<LitInt>,
    pub(crate) validate_exp:       Option<LitBool>,
    pub(crate) validate_nbf:       Option<LitBool>,
    pub(crate) validate_aud:       Option<LitBool>,
    pub(crate) issuers:            Vec<Expr>,
    pub(crate) audiences:          Vec<Expr>,
    pub(crate) subject:            Option<Expr>,
    pub(crate) required_claims:    Option<Vec<Expr>>,
    pub(crate) forward:            bool,
}

impl JwtAttribute {
    pub(crate) fn parse(attr: &Attribute) -> Result<Self, Error> {
        let metas = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;

        let mut key: Option<Expr> = None;
        let mut encoding_key: Option<Expr> = None;
        let mut decoding_key: Option<Expr> = None;
        let mut algorithm: Option<Ident> = None;
        let mut sources: Vec<Source> = Vec::new();
        let mut realm: Option<Expr> = None;
        let mut leeway: Option<LitInt> = None;
        let mut reject_expiring_in: Option<LitInt> = None;
        let mut validate_exp: Option<LitBool> = None;
        let mut validate_nbf: Option<LitBool> = None;
        let mut validate_aud: Option<LitBool> = None;
        let mut issuers: Option<Vec<Expr>> = None;
        let mut audiences: Option<Vec<Expr>> = None;
        let mut subject: Option<Expr> = None;
        let mut required_claims: Option<Vec<Expr>> = None;
        let mut forward: Option<LitBool> = None;

        for meta in metas {
            let name = option_name(&meta)?;
            let span = meta.span();

            match name.as_str() {
                "key" => set_once(&mut key, expr_value(meta)?, &name, span)?,
                "encoding_key" => set_once(&mut encoding_key, expr_value(meta)?, &name, span)?,
                "decoding_key" => set_once(&mut decoding_key, expr_value(meta)?, &name, span)?,
                "algorithm" => set_once(&mut algorithm, algorithm_value(meta)?, &name, span)?,
                "realm" => set_once(&mut realm, expr_value(meta)?, &name, span)?,
                "leeway" => set_once(&mut leeway, int_value(meta)?, &name, span)?,
                "reject_expiring_in" => {
                    set_once(&mut reject_expiring_in, int_value(meta)?, &name, span)?
                },
                "validate_exp" => set_once(&mut validate_exp, bool_value(meta)?, &name, span)?,
                "validate_nbf" => set_once(&mut validate_nbf, bool_value(meta)?, &name, span)?,
                "validate_aud" => set_once(&mut validate_aud, bool_value(meta)?, &name, span)?,
                "issuer" => set_once(&mut issuers, expr_list_value(meta)?, &name, span)?,
                "audience" => set_once(&mut audiences, expr_list_value(meta)?, &name, span)?,
                "subject" => set_once(&mut subject, expr_value(meta)?, &name, span)?,
                "required_claims" => {
                    set_once(&mut required_claims, expr_list_value(meta)?, &name, span)?
                },
                "forward" => set_once(&mut forward, bool_value(meta)?, &name, span)?,
                "header" | "cookie" | "query" => {
                    let source = parse_source(meta, name.as_str())?;

                    if sources.iter().any(|s| s.as_str() == source.as_str()) {
                        return Err(Error::new(
                            span,
                            format!("the JWT source `{name}` is duplicated"),
                        ));
                    }

                    sources.push(source);
                },
                _ => {
                    return Err(Error::new(
                        span,
                        format!("unsupported option `{name}` for the `jwt` attribute"),
                    ));
                },
            }
        }

        let key = match (key, encoding_key, decoding_key) {
            (Some(key), None, None) => Key::Secret(key),
            (None, Some(encoding), Some(decoding)) => Key::Pair {
                encoding,
                decoding,
            },
            (Some(key), ..) => {
                return Err(Error::new_spanned(
                    key,
                    "`key` cannot be used together with `encoding_key` or `decoding_key`",
                ));
            },
            (None, Some(encoding), None) => {
                return Err(Error::new_spanned(encoding, "`decoding_key` is missing"));
            },
            (None, None, Some(decoding)) => {
                return Err(Error::new_spanned(decoding, "`encoding_key` is missing"));
            },
            (None, None, None) => {
                return Err(Error::new(
                    attr.span(),
                    "the `jwt` attribute needs either a `key`, or an `encoding_key` plus a \
                     `decoding_key`",
                ));
            },
        };

        let algorithm = algorithm.unwrap_or_else(|| Ident::new("HS256", attr.span()));

        if matches!(key, Key::Secret(_)) && !algorithm.to_string().starts_with("HS") {
            return Err(Error::new(
                algorithm.span(),
                format!(
                    "`{algorithm}` is not an HMAC algorithm, so it needs an `encoding_key` and a \
                     `decoding_key` instead of a `key`"
                ),
            ));
        }

        if sources.is_empty() {
            sources.push(Source::Header {
                name: None, scheme: None
            });
        }

        if let Some(realm) = realm.as_ref()
            && !sources.iter().any(|source| matches!(source, Source::Header { .. }))
        {
            return Err(Error::new_spanned(
                realm,
                "`realm` needs a `header` source, because a `WWW-Authenticate` challenge only \
                 makes sense for a token which is read from a header",
            ));
        }

        Ok(JwtAttribute {
            key,
            algorithm,
            sources,
            realm,
            leeway,
            reject_expiring_in,
            validate_exp,
            validate_nbf,
            validate_aud,
            issuers: issuers.unwrap_or_default(),
            audiences: audiences.unwrap_or_default(),
            subject,
            required_claims,
            forward: forward.is_some_and(|forward| forward.value()),
        })
    }
}

fn parse_source(meta: Meta, source: &str) -> Result<Source, Error> {
    match source {
        "header" => parse_header_source(meta),
        "cookie" => parse_cookie_source(meta),
        _ => Ok(Source::Query {
            name: source_name(meta, source)?
        }),
    }
}

fn parse_header_source(meta: Meta) -> Result<Source, Error> {
    let mut name: Option<Expr> = None;
    let mut scheme: Option<Expr> = None;

    match meta {
        Meta::Path(_) => (),
        Meta::List(list) => {
            for meta in list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
                let option = option_name(&meta)?;
                let span = meta.span();

                match option.as_str() {
                    "name" => set_once(&mut name, expr_value(meta)?, &option, span)?,
                    "scheme" => set_once(&mut scheme, expr_value(meta)?, &option, span)?,
                    _ => {
                        return Err(Error::new(
                            span,
                            format!("unsupported option `{option}` for the `header` source"),
                        ));
                    },
                }
            }
        },
        meta => {
            return Err(Error::new(
                meta.span(),
                "the `header` source is written as `header` or `header(name = \"…\", scheme = \
                 \"…\")`",
            ));
        },
    }

    Ok(Source::Header {
        name,
        scheme,
    })
}

fn parse_cookie_source(meta: Meta) -> Result<Source, Error> {
    let span = meta.span();

    let mut name: Option<Expr> = None;
    let mut domain: Option<Expr> = None;
    let mut path: Option<Expr> = None;
    let mut secure: Option<LitBool> = None;
    let mut http_only: Option<LitBool> = None;
    let mut same_site: Option<Ident> = None;
    let mut max_age: Option<LitBool> = None;

    match meta {
        Meta::List(list) => {
            for meta in list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
                let option = option_name(&meta)?;
                let span = meta.span();

                match option.as_str() {
                    "name" => set_once(&mut name, expr_value(meta)?, &option, span)?,
                    "domain" => set_once(&mut domain, expr_value(meta)?, &option, span)?,
                    "path" => set_once(&mut path, expr_value(meta)?, &option, span)?,
                    "secure" => set_once(&mut secure, bool_value(meta)?, &option, span)?,
                    "http_only" => set_once(&mut http_only, bool_value(meta)?, &option, span)?,
                    "same_site" => set_once(&mut same_site, same_site_value(meta)?, &option, span)?,
                    "max_age" => set_once(&mut max_age, bool_value(meta)?, &option, span)?,
                    _ => {
                        return Err(Error::new(
                            span,
                            format!("unsupported option `{option}` for the `cookie` source"),
                        ));
                    },
                }
            }
        },
        meta => name = Some(source_name(meta, "cookie")?),
    }

    let Some(name) = name else {
        return Err(Error::new(span, "the `cookie` source needs a `name`"));
    };

    // A browser throws away a `SameSite=None` cookie which is not `Secure`, so this pair can never work.
    // Leaving `secure` out is fine, because Rocket sets the attribute itself when it serves over TLS.
    if let Some(same_site) = same_site.as_ref()
        && same_site == "None"
        && let Some(secure) = secure.as_ref()
        && !secure.value()
    {
        return Err(Error::new(
            secure.span(),
            "`same_site = \"none\"` needs `secure = true`, because a browser drops a \
             `SameSite=None` cookie which is not `Secure`",
        ));
    }

    Ok(Source::Cookie(Box::new(CookieOptions {
        name,
        domain,
        path,
        secure,
        http_only,
        same_site,
        max_age,
    })))
}

/// Reads the name of a source written in its short form, like `cookie = "access_token"`.
fn source_name(meta: Meta, source: &str) -> Result<Expr, Error> {
    match meta {
        Meta::NameValue(name_value) => Ok(name_value.value),
        meta => Err(Error::new(
            meta.span(),
            format!("the `{source}` source needs a name, like `{source} = \"access_token\"`"),
        )),
    }
}

fn option_name(meta: &Meta) -> Result<String, Error> {
    match meta.path().get_ident() {
        Some(ident) => Ok(ident.to_string().to_ascii_lowercase()),
        None => Err(Error::new(meta.path().span(), "expected an option name")),
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str, span: Span) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::new(span, format!("the option `{name}` is duplicated")));
    }

    *slot = Some(value);

    Ok(())
}

fn expr_value(meta: Meta) -> Result<Expr, Error> {
    let name = option_name(&meta)?;

    match meta {
        Meta::NameValue(name_value) => Ok(name_value.value),
        meta => Err(Error::new(meta.span(), format!("the option `{name}` needs a value"))),
    }
}

/// Reads either a single value or an array of values, like `audience = "a"` or `audience = ["a", "b"]`.
fn expr_list_value(meta: Meta) -> Result<Vec<Expr>, Error> {
    match expr_value(meta)? {
        Expr::Array(array) => Ok(array.elems.into_iter().collect()),
        expr => Ok(vec![expr]),
    }
}

fn int_value(meta: Meta) -> Result<LitInt, Error> {
    let name = option_name(&meta)?;
    let span = meta.span();

    match expr_value(meta)? {
        Expr::Lit(ExprLit {
            lit: Lit::Int(lit), ..
        }) => Ok(lit),
        _ => Err(Error::new(span, format!("the option `{name}` needs an integer"))),
    }
}

/// Reads a boolean option, where writing the option name alone means `true`.
fn bool_value(meta: Meta) -> Result<LitBool, Error> {
    let name = option_name(&meta)?;
    let span = meta.span();

    match meta {
        Meta::Path(_) => Ok(LitBool::new(true, span)),
        meta => match expr_value(meta)? {
            Expr::Lit(ExprLit {
                lit: Lit::Bool(lit), ..
            }) => Ok(lit),
            _ => Err(Error::new(span, format!("the option `{name}` needs a boolean"))),
        },
    }
}

/// Reads `same_site = "strict" | "lax" | "none"` and turns it into a `rocket::http::SameSite` variant name.
fn same_site_value(meta: Meta) -> Result<Ident, Error> {
    let span = meta.span();

    let lit: LitStr = match expr_value(meta)? {
        Expr::Lit(ExprLit {
            lit: Lit::Str(lit), ..
        }) => lit,
        _ => {
            return Err(Error::new(span, "the option `same_site` needs a string"));
        },
    };

    let variant = match lit.value().to_ascii_lowercase().as_str() {
        "strict" => "Strict",
        "lax" => "Lax",
        "none" => "None",
        _ => {
            return Err(Error::new(
                lit.span(),
                "the option `same_site` needs to be `\"strict\"`, `\"lax\"`, or `\"none\"`",
            ));
        },
    };

    Ok(Ident::new(variant, lit.span()))
}

fn algorithm_value(meta: Meta) -> Result<Ident, Error> {
    let span = meta.span();

    let ident = match expr_value(meta)? {
        Expr::Path(path) => match path.path.get_ident() {
            Some(ident) => ident.clone(),
            None => {
                return Err(Error::new(span, "the option `algorithm` needs an algorithm name"));
            },
        },
        _ => {
            return Err(Error::new(span, "the option `algorithm` needs an algorithm name"));
        },
    };

    if !ALGORITHMS.contains(&ident.to_string().as_str()) {
        return Err(Error::new(
            ident.span(),
            format!("`{ident}` is not a supported algorithm; use one of {}", ALGORITHMS.join(", ")),
        ));
    }

    Ok(ident)
}
