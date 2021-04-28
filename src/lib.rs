/*!
# `jwt-authorization` Request Guard for Rocket Framework

This crate provides a procedural macro to create request guards used for authorization.

See `examples`.
*/

extern crate proc_macro;

extern crate syn;

#[macro_use]
extern crate quote;

mod panic;

use proc_macro::TokenStream;
use syn::{DeriveInput, Expr, ExprLit, ExprPath, Lit, Meta, NestedMeta, Path};

enum Source {
    Header,
    Cookie(Box<Expr>),
    Query(Box<Expr>),
    // TODO currently it's hard to be implemented, just ignore it
    #[allow(dead_code)]
    Body(Box<Expr>),
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
    fn from<S: AsRef<str>>(name: S, expr: Box<Expr>) -> Option<Source> {
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

        for source in sources {
            if source.as_str() == name {
                return Some(source);
            }
        }

        None
    }

    #[inline]
    fn search_cookie_get_expr(sources: &[Source]) -> Option<&Expr> {
        for source in sources.iter() {
            if let Source::Cookie(expr) = source {
                return Some(expr.as_ref());
            }
        }

        None
    }
}

fn derive_input_handler(ast: DeriveInput) -> TokenStream {
    let correct_usage_for_jwt_attribute = &[
        "#[jwt(\"key\")]",
        "#[jwt(PATH)]",
        "#[jwt(\"key\", sha2::Sha512)]",
        "#[jwt(PATH, sha2::Sha512)]",
        "#[jwt(PATH, sha2::Sha512, Header)]",
        "#[jwt(PATH, sha2::Sha512, Cookie(\"access_token\"), Header, Query(PATH))]",
    ];

    for attr in ast.attrs.iter() {
        if let Some(attr_meta_name) = attr.path.get_ident() {
            if attr_meta_name == "jwt" {
                let attr_meta = attr.parse_meta().unwrap();

                if let Meta::List(list) = attr_meta {
                    let mut iter = list.nested.into_iter();

                    let key: Expr = match iter.next() {
                        Some(p) => {
                            match p {
                                NestedMeta::Lit(l) => {
                                    match l {
                                        Lit::Str(s) => {
                                            Expr::Lit(ExprLit {
                                                attrs: Vec::new(),
                                                lit: Lit::Str(s),
                                            })
                                        }
                                        _ => {
                                            panic::attribute_incorrect_format(
                                                "jwt",
                                                correct_usage_for_jwt_attribute,
                                            )
                                        }
                                    }
                                }
                                NestedMeta::Meta(m) => {
                                    match m {
                                        Meta::Path(p) => {
                                            Expr::Path(ExprPath {
                                                attrs: Vec::new(),
                                                qself: None,
                                                path: p,
                                            })
                                        }
                                        _ => {
                                            panic::attribute_incorrect_format(
                                                "jwt",
                                                correct_usage_for_jwt_attribute,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            panic::attribute_incorrect_format(
                                "jwt",
                                correct_usage_for_jwt_attribute,
                            )
                        }
                    };

                    let (algorithm, sources): (Path, Vec<Source>) = match iter.next() {
                        Some(p) => {
                            match p {
                                NestedMeta::Meta(Meta::Path(p)) => {
                                    let mut sources = Vec::new();

                                    for p in iter {
                                        match p {
                                            NestedMeta::Meta(m) => {
                                                let attr_name = match m.path().get_ident() {
                                                    Some(ident) => {
                                                        ident.to_string().to_ascii_lowercase()
                                                    }
                                                    None => {
                                                        panic::attribute_incorrect_format(
                                                            "jwt",
                                                            correct_usage_for_jwt_attribute,
                                                        );
                                                    }
                                                };

                                                if Source::search(&sources, attr_name.as_str())
                                                    .is_some()
                                                {
                                                    panic::duplicated_source(attr_name.as_str());
                                                }

                                                match m {
                                                    Meta::Path(_) => {
                                                        if attr_name.eq_ignore_ascii_case("header")
                                                        {
                                                            sources.push(Source::Header);
                                                        } else {
                                                            panic::attribute_incorrect_format(
                                                                "jwt",
                                                                correct_usage_for_jwt_attribute,
                                                            );
                                                        }
                                                    }
                                                    Meta::NameValue(v) => {
                                                        match v.lit {
                                                            Lit::Str(s) => {
                                                                let expr =
                                                                    Box::new(Expr::Lit(ExprLit {
                                                                        attrs: Vec::new(),
                                                                        lit: Lit::Str(s),
                                                                    }));

                                                                match Source::from(attr_name, expr) {
                                                                Some(source) => sources.push(source),
                                                                None => panic::attribute_incorrect_format(
                                                                    "jwt",
                                                                    correct_usage_for_jwt_attribute,
                                                                )
                                                            }
                                                            }
                                                            _ => {
                                                                panic::attribute_incorrect_format(
                                                                    "jwt",
                                                                    correct_usage_for_jwt_attribute,
                                                                )
                                                            }
                                                        }
                                                    }
                                                    Meta::List(list) => {
                                                        let mut iter = list.nested.into_iter();

                                                        if let Some(p) = iter.next() {
                                                            match p {
                                                                NestedMeta::Meta(m) => {
                                                                    match m {
                                                                        Meta::Path(path) => {
                                                                            let expr =
                                                                                Box::new(Expr::Path(ExprPath {
                                                                                    attrs: Vec::new(),
                                                                                    qself: None,
                                                                                    path,
                                                                                }));

                                                                            match Source::from(attr_name, expr) {
                                                                                Some(source) => sources.push(source),
                                                                                None => panic::attribute_incorrect_format(
                                                                                    "jwt",
                                                                                    correct_usage_for_jwt_attribute,
                                                                                )
                                                                            }
                                                                        }
                                                                        _ => {
                                                                            panic::attribute_incorrect_format(
                                                                                "jwt",
                                                                                correct_usage_for_jwt_attribute,
                                                                            )
                                                                        }
                                                                    }
                                                                }
                                                                NestedMeta::Lit(l) => {
                                                                    match l {
                                                                        Lit::Str(s) => {
                                                                            let expr =
                                                                                Box::new(Expr::Lit(ExprLit {
                                                                                    attrs: Vec::new(),
                                                                                    lit: Lit::Str(s),
                                                                                }));

                                                                            match Source::from(attr_name, expr) {
                                                                                Some(source) => sources.push(source),
                                                                                None => panic::attribute_incorrect_format(
                                                                                    "jwt",
                                                                                    correct_usage_for_jwt_attribute,
                                                                                )
                                                                            }
                                                                        }
                                                                        _ => {
                                                                            panic::attribute_incorrect_format(
                                                                                "jwt",
                                                                                correct_usage_for_jwt_attribute,
                                                                            )
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            panic::attribute_incorrect_format(
                                                                "jwt",
                                                                correct_usage_for_jwt_attribute,
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            _ => {
                                                panic::attribute_incorrect_format(
                                                    "jwt",
                                                    correct_usage_for_jwt_attribute,
                                                )
                                            }
                                        }
                                    }

                                    if sources.is_empty() {
                                        sources.push(Source::Header);
                                    }

                                    (p, sources)
                                }
                                _ => {
                                    panic::attribute_incorrect_format(
                                        "jwt",
                                        correct_usage_for_jwt_attribute,
                                    )
                                }
                            }
                        }
                        None => {
                            (syn::parse2(quote!(::sha2::Sha256)).unwrap(), vec![Source::Header])
                        }
                    };

                    let name = &ast.ident;
                    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

                    let get_jwt_hasher = quote! {
                        #[inline]
                        pub fn get_jwt_hasher() -> &'static hmac::Hmac<#algorithm> {
                            static START: ::std::sync::Once = ::std::sync::Once::new();
                            static mut HMAC: Option<hmac::Hmac<#algorithm>> = None;

                            unsafe {
                                START.call_once(|| {
                                    use ::hmac::{Hmac, NewMac};

                                    HMAC = Some(Hmac::new_varkey(unsafe {#key}.as_ref()).unwrap())
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
                                }
                                Source::Cookie(expr) => {
                                    quote! {
                                        else if let Some(token) = request.cookies().get(unsafe {#expr}) {
                                            match #name::verify_jwt_token(token.value()) {
                                                Ok(o) => Some(o),
                                                Err(_) => {
                                                    #name::remove_cookie(&mut request.cookies());

                                                    None
                                                }
                                            }
                                        }
                                    }
                                }
                                Source::Query(expr) => {
                                    quote! {
                                        else if let Some(token) = request.get_query_value(unsafe {#expr}) {
                                            let token: &::rocket::http::RawStr = token.unwrap();

                                            match #name::verify_jwt_token(token) {
                                                Ok(o) => Some(o),
                                                Err(_) => None
                                            }
                                        }
                                    }
                                }
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
                } else {
                    panic::attribute_incorrect_format("jwt", correct_usage_for_jwt_attribute);
                }
            }
        }
    }

    panic::jwt_not_found();
}

#[proc_macro_derive(JWT, attributes(jwt))]
pub fn jwt_derive(input: TokenStream) -> TokenStream {
    derive_input_handler(syn::parse(input).unwrap())
}
