/*!
# `jwt-authorization` Request Guard for Rocket Framework

This crate provides a procedural macro to create request guards used for authorization.

See `examples`.
*/

mod panic;

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    DeriveInput, Expr, Lit, Meta, Path, Token,
};

const CORRECT_USAGE_FOR_JWT_ATTRIBUTE: &[&str] = &[
    "#[jwt(\"key\")]",
    "#[jwt(PATH)]",
    "#[jwt(\"key\", sha2::Sha512)]",
    "#[jwt(PATH, sha2::Sha512)]",
    "#[jwt(PATH, sha2::Sha512, Header)]",
    "#[jwt(PATH, sha2::Sha512, Cookie(\"access_token\"), Header, Query(PATH))]",
];

enum Source {
    Header,
    Cookie(Expr),
    Query(Expr),
    // TODO currently it's hard to be implemented, just ignore it
    #[allow(dead_code)]
    Body(Expr),
}

impl Source {
    #[inline]
    fn as_str(&self) -> &'static str {
        match self {
            Source::Header => "header",
            Source::Cookie(_) => "cookie",
            Source::Query(_) => "query",
            Source::Body(_) => "body",
        }
    }

    #[inline]
    fn from<S: AsRef<str>>(name: S, expr: Expr) -> Option<Source> {
        let name = name.as_ref();

        match name {
            "query" => Some(Source::Query(expr)),
            "cookie" => Some(Source::Cookie(expr)),
            "body" => unimplemented!(),
            _ => None,
        }
    }

    #[inline]
    fn search<S: AsRef<str>>(sources: &[Source], name: S) -> Option<&Source> {
        let name = name.as_ref();

        sources.iter().find(|source| source.as_str() == name)
    }

    #[inline]
    fn search_cookie_get_expr(sources: &[Source]) -> Option<&Expr> {
        for source in sources.iter() {
            if let Source::Cookie(expr) = source {
                return Some(expr);
            }
        }

        None
    }
}

struct Parser2 {
    expr: Expr,
}

impl Parse for Parser2 {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self, syn::Error> {
        match input.parse::<Expr>() {
            Ok(expr) => {
                let pass = match &expr {
                    Expr::Path(_) => true,
                    Expr::Lit(lit) => matches!(lit.lit, Lit::Str(_)),
                    _ => false,
                };

                if !pass {
                    panic::attribute_incorrect_format("jwt", CORRECT_USAGE_FOR_JWT_ATTRIBUTE);
                }

                Ok(Parser2 {
                    expr,
                })
            },
            _ => panic::attribute_incorrect_format("jwt", CORRECT_USAGE_FOR_JWT_ATTRIBUTE),
        }
    }
}

struct Parser {
    key:       Expr,
    algorithm: Path,
    sources:   Vec<Source>,
}

impl Parse for Parser {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self, syn::Error> {
        let key = input.parse::<Parser2>()?.expr;

        let (algorithm, sources): (Path, Vec<Source>) = {
            if input.is_empty() {
                (syn::parse2(quote!(::sha2::Sha256))?, vec![Source::Header])
            } else {
                input.parse::<Token!(,)>()?;

                match input.parse::<Path>() {
                    Ok(p) => {
                        let mut sources = Vec::new();

                        while !input.is_empty() {
                            input.parse::<Token!(,)>()?;

                            let m = input.parse::<Meta>()?;

                            let attr_name = match m.path().get_ident() {
                                Some(ident) => ident.to_string().to_ascii_lowercase(),
                                None => {
                                    panic::attribute_incorrect_format(
                                        "jwt",
                                        CORRECT_USAGE_FOR_JWT_ATTRIBUTE,
                                    );
                                },
                            };

                            if Source::search(&sources, attr_name.as_str()).is_some() {
                                panic::duplicated_source(attr_name.as_str());
                            }

                            match m {
                                Meta::Path(_) => {
                                    if attr_name.eq_ignore_ascii_case("header") {
                                        sources.push(Source::Header);
                                    } else {
                                        panic::attribute_incorrect_format(
                                            "jwt",
                                            CORRECT_USAGE_FOR_JWT_ATTRIBUTE,
                                        );
                                    }
                                },
                                Meta::NameValue(v) => {
                                    let expr = v.value;

                                    let pass = match &expr {
                                        Expr::Path(_) => true,
                                        Expr::Lit(lit) => matches!(lit.lit, Lit::Str(_)),
                                        _ => false,
                                    };

                                    if !pass {
                                        panic::attribute_incorrect_format(
                                            "jwt",
                                            CORRECT_USAGE_FOR_JWT_ATTRIBUTE,
                                        );
                                    }

                                    match Source::from(attr_name, expr) {
                                        Some(source) => sources.push(source),
                                        None => panic::attribute_incorrect_format(
                                            "jwt",
                                            CORRECT_USAGE_FOR_JWT_ATTRIBUTE,
                                        ),
                                    }
                                },
                                Meta::List(list) => {
                                    let parsed: Parser2 = list.parse_args()?;

                                    let expr = parsed.expr;

                                    match Source::from(attr_name, expr) {
                                        Some(source) => sources.push(source),
                                        None => panic::attribute_incorrect_format(
                                            "jwt",
                                            CORRECT_USAGE_FOR_JWT_ATTRIBUTE,
                                        ),
                                    }
                                },
                            }
                        }

                        if sources.is_empty() {
                            sources.push(Source::Header);
                        }

                        (p, sources)
                    },
                    Err(_) => {
                        panic::attribute_incorrect_format("jwt", CORRECT_USAGE_FOR_JWT_ATTRIBUTE)
                    },
                }
            }
        };

        Ok(Parser {
            key,
            algorithm,
            sources,
        })
    }
}

fn derive_input_handler(ast: DeriveInput) -> TokenStream {
    for attr in ast.attrs {
        if attr.path().is_ident("jwt") {
            match attr.meta {
                Meta::List(list) => {
                    let parsed: Parser = list.parse_args().unwrap();

                    let algorithm = parsed.algorithm;
                    let key = parsed.key;
                    let sources = parsed.sources;

                    let name = &ast.ident;
                    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

                    let get_jwt_hasher = quote! {
                        #[inline]
                        pub fn get_jwt_hasher() -> &'static hmac::Hmac<#algorithm> {
                            static START: ::std::sync::Once = ::std::sync::Once::new();
                            static mut HMAC: Option<hmac::Hmac<#algorithm>> = None;

                            unsafe {
                                START.call_once(|| {
                                    use ::hmac::Hmac;
                                    use ::hmac::digest::KeyInit;

                                    HMAC = Some(Hmac::new_from_slice(unsafe {#key}.as_ref()).unwrap())
                                });

                                HMAC.as_ref().unwrap()
                            }
                        }
                    };

                    let get_jwt_token = quote! {
                        #[inline]
                        pub fn get_jwt_token(&self) -> String {
                            use ::jwt::SignWithKey;

                            let hasher = Self::get_jwt_hasher();

                            self.sign_with_key(hasher).unwrap()
                        }
                    };

                    let verify_jwt_token = quote! {
                        #[inline]
                        pub fn verify_jwt_token<S: AsRef<str>>(token: S) -> Result<Self, ::jwt::Error> {
                            use ::jwt::VerifyWithKey;

                            let token = token.as_ref();

                            let hasher = Self::get_jwt_hasher();

                            token.verify_with_key(hasher)
                        }
                    };

                    let (set_cookie, set_cookie_insecure, remove_cookie) = if let Some(expr) =
                        Source::search_cookie_get_expr(&sources)
                    {
                        let set_cookie = quote! {
                            #[inline]
                            pub fn set_cookie(&self, cookies: &::rocket::http::CookieJar) {
                                let mut cookie = ::rocket::http::Cookie::new(unsafe {#expr}, self.get_jwt_token());

                                cookie.set_secure(true);

                                cookies.add(cookie);
                            }
                        };

                        let set_cookie_insecure = quote! {
                            #[inline]
                            pub fn set_cookie_insecure(&self, cookies: &::rocket::http::CookieJar) {
                                let mut cookie = ::rocket::http::Cookie::new(unsafe {#expr}, self.get_jwt_token());

                                cookie.set_same_site(::rocket::http::SameSite::Strict);

                                cookies.add(cookie);
                            }
                        };

                        let remove_cookie = quote! {
                            #[inline]
                            pub fn remove_cookie(cookies: &::rocket::http::CookieJar) {
                                cookies.remove(::rocket::http::Cookie::named(unsafe {#expr}));
                            }
                        };

                        (set_cookie, set_cookie_insecure, remove_cookie)
                    } else {
                        (quote!(), quote!(), quote!())
                    };

                    let (from_request, from_request_cache) = {
                        let mut source_streams = Vec::with_capacity(sources.len());

                        for source in sources.iter() {
                            let source_stream = match source {
                                Source::Header => {
                                    quote! {
                                        else if let Some(authorization) = request.headers().get("authorization").next() {
                                            if let Some(token) = authorization.strip_prefix("Bearer ") {
                                                match #name::verify_jwt_token(token) {
                                                    Ok(o) => Some(o),
                                                    Err(_) => None
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                    }
                                },
                                Source::Cookie(expr) => {
                                    quote! {
                                        else if let Some(token) = request.cookies().get(unsafe {#expr}) {
                                            match #name::verify_jwt_token(token.value()) {
                                                Ok(o) => Some(o),
                                                Err(_) => {
                                                    #name::remove_cookie(&request.cookies());

                                                    None
                                                }
                                            }
                                        }
                                    }
                                },
                                Source::Query(expr) => {
                                    quote! {
                                        else if let Some(token) = request.query_value(unsafe {#expr}) {
                                            let token: &str = token.unwrap();

                                            match #name::verify_jwt_token(token) {
                                                Ok(o) => Some(o),
                                                Err(_) => None
                                            }
                                        }
                                    }
                                },
                                _ => unimplemented!(),
                            };

                            source_streams.push(source_stream);
                        }

                        let from_request_body = quote! {
                            if false {
                                None
                            }
                            #(
                                #source_streams
                            )*
                            else {
                                None
                            }
                        };

                        let from_request = quote! {
                            #[rocket::async_trait]
                            impl<'r> ::rocket::request::FromRequest<'r> for #name {
                                type Error = ();

                                async fn from_request(request: &'r ::rocket::request::Request<'_>) -> ::rocket::request::Outcome<Self, Self::Error> {
                                    match #from_request_body {
                                        Some(o) => ::rocket::outcome::Outcome::Success(o),
                                        None => ::rocket::outcome::Outcome::Forward(()),
                                    }
                                }
                            }
                        };

                        let from_request_cache = quote! {
                            #[rocket::async_trait]
                            impl<'r> ::rocket::request::FromRequest<'r> for &'r #name {
                                type Error = ();

                                async fn from_request(request: &'r ::rocket::request::Request<'_>) -> ::rocket::request::Outcome<Self, Self::Error> {
                                    let cache = request.local_cache(|| {
                                        #from_request_body
                                    });

                                    match cache.as_ref() {
                                        Some(o) => ::rocket::outcome::Outcome::Success(o),
                                        None => ::rocket::outcome::Outcome::Forward(()),
                                    }
                                }
                            }
                        };

                        (from_request, from_request_cache)
                    };

                    let jwt_impl = quote! {
                        impl #impl_generics #name #ty_generics #where_clause {
                            #get_jwt_hasher

                            #get_jwt_token

                            #verify_jwt_token

                            #set_cookie

                            #set_cookie_insecure

                            #remove_cookie
                        }

                        #from_request

                        #from_request_cache
                    };

                    return jwt_impl.into();
                },
                _ => panic::attribute_incorrect_format("jwt", CORRECT_USAGE_FOR_JWT_ATTRIBUTE),
            }
        }
    }

    panic::jwt_not_found();
}

#[proc_macro_derive(JWT, attributes(jwt))]
pub fn jwt_derive(input: TokenStream) -> TokenStream {
    derive_input_handler(syn::parse(input).unwrap())
}
