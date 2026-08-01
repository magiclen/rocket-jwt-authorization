use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Error, Fields, Ident, Type};

use crate::attribute::{JwtAttribute, Key, Source};

/// The integer types an `exp` field is allowed to have for the fast path below.
const TIMESTAMP_TYPES: [&str; 6] = ["u64", "u32", "usize", "i64", "i32", "isize"];

/// Tells whether the claims have a plain `exp` field, so that `expiration` can read it directly instead of serializing everything.
/// A field carrying a `serde` attribute is skipped, because it may be renamed or serialized as something which is not a timestamp.
fn has_plain_exp_field(ast: &DeriveInput) -> bool {
    let Data::Struct(data) = &ast.data else {
        return false;
    };

    let Fields::Named(fields) = &data.fields else {
        return false;
    };

    fields.named.iter().any(|field| {
        if !field.ident.as_ref().is_some_and(|ident| ident == "exp") {
            return false;
        }

        if field.attrs.iter().any(|attr| attr.path().is_ident("serde")) {
            return false;
        }

        match &field.ty {
            Type::Path(path) => path
                .path
                .get_ident()
                .is_some_and(|ident| TIMESTAMP_TYPES.contains(&ident.to_string().as_str())),
            _ => false,
        }
    })
}

fn runtime_crate() -> Result<TokenStream, Error> {
    let found = crate_name("rocket-jwt-authorization").map_err(|error| {
        Error::new(
            Span::call_site(),
            format!("cannot find the `rocket-jwt-authorization` crate: {error}"),
        )
    })?;

    Ok(match found {
        FoundCrate::Itself => quote!(::rocket_jwt_authorization),
        FoundCrate::Name(name) => {
            let name = Ident::new(&name, Span::call_site());

            quote!(::#name)
        },
    })
}

pub(crate) fn expand(ast: DeriveInput) -> Result<TokenStream, Error> {
    let mut attrs = ast.attrs.iter().filter(|attr| attr.path().is_ident("jwt"));

    let Some(attr) = attrs.next() else {
        return Err(Error::new(ast.ident.span(), "cannot find the `jwt` attribute"));
    };

    if let Some(attr) = attrs.next() {
        return Err(Error::new_spanned(attr, "the `jwt` attribute is duplicated"));
    }

    if !ast.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &ast.generics,
            "`JWT` cannot be derived for a generic type, because the claims of a token are always \
             a concrete type",
        ));
    }

    let attribute = JwtAttribute::parse(attr)?;

    let name = &ast.ident;
    let krate = runtime_crate()?;
    let private = quote!(#krate::__private);
    let rocket = quote!(#krate::__private::rocket);

    let algorithm = &attribute.algorithm;

    let (key_storage, key_getters) = match &attribute.key {
        Key::Secret(secret) => {
            let initialize_keys = quote! {
                let secret = #secret;
                let secret = ::core::convert::AsRef::<[u8]>::as_ref(&secret);

                (
                    #krate::EncodingKey::from_secret(secret),
                    #krate::DecodingKey::from_secret(secret),
                )
            };

            (
                quote! {
                    static KEYS: #private::OnceLock<(#krate::EncodingKey, #krate::DecodingKey)> = #private::OnceLock::new();
                },
                quote! {
                    #[inline]
                    fn jwt_encoding_key() -> &'static #krate::EncodingKey {
                        &KEYS.get_or_init(|| { #initialize_keys }).0
                    }

                    #[inline]
                    fn jwt_decoding_key() -> &'static #krate::DecodingKey {
                        &KEYS.get_or_init(|| { #initialize_keys }).1
                    }
                },
            )
        },
        Key::Pair {
            encoding,
            decoding,
        } => (quote!(), quote! {
            #[inline]
            fn jwt_encoding_key() -> &'static #krate::EncodingKey {
                static KEY: #private::OnceLock<#krate::EncodingKey> = #private::OnceLock::new();

                KEY.get_or_init(|| #encoding)
            }

            #[inline]
            fn jwt_decoding_key() -> &'static #krate::DecodingKey {
                static KEY: #private::OnceLock<#krate::DecodingKey> = #private::OnceLock::new();

                KEY.get_or_init(|| #decoding)
            }
        }),
    };

    let mut validation_setters: Vec<TokenStream> = Vec::new();

    if let Some(leeway) = &attribute.leeway {
        validation_setters.push(quote!(validation.leeway = #leeway;));
    }

    if let Some(reject_expiring_in) = &attribute.reject_expiring_in {
        validation_setters
            .push(quote!(validation.reject_tokens_expiring_in_less_than = #reject_expiring_in;));
    }

    if let Some(validate_exp) = &attribute.validate_exp {
        validation_setters.push(quote!(validation.validate_exp = #validate_exp;));
    }

    if let Some(validate_nbf) = &attribute.validate_nbf {
        validation_setters.push(quote!(validation.validate_nbf = #validate_nbf;));
    }

    if let Some(validate_aud) = &attribute.validate_aud {
        validation_setters.push(quote!(validation.validate_aud = #validate_aud;));
    }

    if let Some(subject) = &attribute.subject {
        // `Validation` has `set_issuer` and `set_audience`, but no setter for `sub`.
        validation_setters.push(quote! {
            validation.sub = ::core::option::Option::Some(::std::string::ToString::to_string(&#subject));
        });
    }

    if !attribute.issuers.is_empty() {
        let issuers = &attribute.issuers;

        validation_setters.push(quote!(validation.set_issuer(&[#(#issuers),*]);));
    }

    if !attribute.audiences.is_empty() {
        let audiences = &attribute.audiences;

        validation_setters.push(quote!(validation.set_audience(&[#(#audiences),*]);));
    }

    if let Some(required_claims) = &attribute.required_claims {
        validation_setters
            .push(quote!(validation.set_required_spec_claims(&[#(#required_claims),*]);));
    }

    let expiration_impl = if has_plain_exp_field(&ast) {
        quote! {
            #[inline]
            fn expiration(&self) -> ::core::option::Option<u64> {
                ::core::convert::TryFrom::try_from(self.exp).ok()
            }
        }
    } else {
        quote!()
    };

    let jwt_impl = quote! {
        const _: () = {
            #key_storage

            impl #krate::Jwt for #name {
                #key_getters

                #[inline]
                fn jwt_header() -> &'static #krate::Header {
                    static HEADER: #private::OnceLock<#krate::Header> = #private::OnceLock::new();

                    HEADER.get_or_init(|| #krate::Header::new(#krate::Algorithm::#algorithm))
                }

                #[inline]
                fn jwt_validation() -> &'static #krate::Validation {
                    static VALIDATION: #private::OnceLock<#krate::Validation> = #private::OnceLock::new();

                    VALIDATION.get_or_init(|| {
                        let mut validation = #krate::Validation::new(#krate::Algorithm::#algorithm);

                        #(#validation_setters)*

                        validation
                    })
                }

                #expiration_impl
            }
        };
    };

    let jwt_cookie_impl = match attribute.sources.iter().find_map(|source| match source {
        Source::Cookie(options) => Some(options),
        _ => None,
    }) {
        Some(options) => {
            let cookie_name = &options.name;

            let mut config_setters: Vec<TokenStream> = Vec::new();

            if let Some(domain) = &options.domain {
                config_setters.push(quote!(.domain(#domain)));
            }

            if let Some(path) = &options.path {
                config_setters.push(quote!(.path(#path)));
            }

            if let Some(secure) = &options.secure {
                config_setters.push(quote!(.secure(#secure)));
            }

            if let Some(http_only) = &options.http_only {
                config_setters.push(quote!(.http_only(#http_only)));
            }

            if let Some(same_site) = &options.same_site {
                config_setters.push(quote!(.same_site(#rocket::http::SameSite::#same_site)));
            }

            if let Some(max_age) = &options.max_age {
                config_setters.push(quote!(.max_age(#max_age)));
            }

            quote! {
                impl #krate::JwtCookie for #name {
                    #[inline]
                    fn jwt_cookie_config() -> &'static #krate::CookieConfig {
                        static CONFIG: #private::OnceLock<#krate::CookieConfig> = #private::OnceLock::new();

                        CONFIG.get_or_init(|| #krate::CookieConfig::new(#cookie_name) #(#config_setters)*)
                    }
                }
            }
        },
        None => quote!(),
    };

    // A challenge names the scheme the `header` source expects, so a guard which never looks at a header has nothing to challenge with.
    let header_scheme = attribute.sources.iter().find_map(|source| match source {
        Source::Header {
            scheme, ..
        } => Some(scheme),
        _ => None,
    });

    let jwt_challenge_impl = match header_scheme {
        Some(scheme) => {
            let scheme = match scheme {
                Some(scheme) => quote!(#scheme),
                None => quote!("Bearer"),
            };

            // Both options take any `AsRef<str>`, and the config owns its strings, so copy them once when it is built.
            let realm_setter = match &attribute.realm {
                Some(realm) => quote! {
                    .realm(::std::borrow::ToOwned::to_owned(::core::convert::AsRef::<str>::as_ref(&#realm)))
                },
                None => quote!(),
            };

            quote! {
                impl #krate::JwtChallenge for #name {
                    #[inline]
                    fn jwt_challenge_config() -> &'static #krate::ChallengeConfig {
                        static CONFIG: #private::OnceLock<#krate::ChallengeConfig> = #private::OnceLock::new();

                        CONFIG.get_or_init(|| {
                            #krate::ChallengeConfig::new(::std::borrow::ToOwned::to_owned(::core::convert::AsRef::<str>::as_ref(&#scheme)))
                                #realm_setter
                        })
                    }
                }
            }
        },
        None => quote!(),
    };

    let record_challenge = match header_scheme {
        Some(_) => quote! {
            if let ::core::result::Result::Err(error) = &result {
                #private::record_challenge(request, <#name as #krate::JwtChallenge>::jwt_challenge_config(), error);
            }
        },
        None => quote!(),
    };

    let mut source_blocks: Vec<TokenStream> = Vec::with_capacity(attribute.sources.len());

    for source in attribute.sources.iter() {
        let block = match source {
            Source::Header {
                name,
                scheme,
            } => {
                let header_name = match name {
                    Some(name) => quote!(#name),
                    None => quote!("authorization"),
                };

                let scheme = match scheme {
                    Some(scheme) => quote!(#scheme),
                    None => quote!("Bearer"),
                };

                quote! {
                    if let ::core::option::Option::Some(value) = request.headers().get_one(::core::convert::AsRef::<str>::as_ref(&#header_name)) {
                        if let ::core::option::Option::Some(token) = #private::scheme_token(value, ::core::convert::AsRef::<str>::as_ref(&#scheme)) {
                            return <Self as #krate::Jwt>::verify(token).map_err(#krate::JwtGuardError::Invalid);
                        }
                    }
                }
            },
            Source::Cookie(_) => {
                quote! {
                    {
                        let cookies = request.cookies();

                        if let ::core::option::Option::Some(cookie) = cookies.get(<Self as #krate::JwtCookie>::jwt_cookie_config().name()) {
                            return match <Self as #krate::Jwt>::verify(cookie.value()) {
                                ::core::result::Result::Ok(claims) => ::core::result::Result::Ok(claims),
                                ::core::result::Result::Err(error) => {
                                    // A token that cannot be verified is never going to work, so stop the browser from sending it again.
                                    <Self as #krate::JwtCookie>::remove_cookie(cookies);
                                    // Rocket resets the cookie changes of a request whose guard fails, so leave the removal for `JwtFairing` as well.
                                    #private::record_cookie_removal(request, <Self as #krate::JwtCookie>::jwt_cookie_config());

                                    ::core::result::Result::Err(#krate::JwtGuardError::Invalid(error))
                                },
                            };
                        }
                    }
                }
            },
            Source::Query {
                name,
            } => {
                quote! {
                    if let ::core::option::Option::Some(token) = request.query_value::<&str>(::core::convert::AsRef::<str>::as_ref(&#name)).and_then(::core::result::Result::ok) {
                        return <Self as #krate::Jwt>::verify(token).map_err(#krate::JwtGuardError::Invalid);
                    }
                }
            },
        };

        source_blocks.push(block);
    }

    let from_jwt_request_impl = quote! {
        impl #krate::FromJwtRequest for #name {
            fn from_jwt_request(request: &#rocket::request::Request<'_>) -> ::core::result::Result<Self, #krate::JwtGuardError> {
                #(#source_blocks)*

                ::core::result::Result::Err(#krate::JwtGuardError::Missing)
            }
        }
    };

    let (error_arm, cached_error_arm) = if attribute.forward {
        let arm = quote! {
            ::core::result::Result::Err(_) => #rocket::outcome::Outcome::Forward(#rocket::http::Status::Unauthorized),
        };

        (arm.clone(), arm)
    } else {
        (
            quote! {
                ::core::result::Result::Err(error) => #rocket::outcome::Outcome::Error((#rocket::http::Status::Unauthorized, error)),
            },
            quote! {
                ::core::result::Result::Err(error) => #rocket::outcome::Outcome::Error((#rocket::http::Status::Unauthorized, ::core::clone::Clone::clone(error))),
            },
        )
    };

    let from_request_impl = quote! {
        #[#rocket::async_trait]
        impl<'r> #rocket::request::FromRequest<'r> for #name {
            type Error = #krate::JwtGuardError;

            async fn from_request(request: &'r #rocket::request::Request<'_>) -> #rocket::request::Outcome<Self, Self::Error> {
                let result = <Self as #krate::FromJwtRequest>::from_jwt_request(request);

                #record_challenge

                match result {
                    ::core::result::Result::Ok(claims) => #rocket::outcome::Outcome::Success(claims),
                    #error_arm
                }
            }
        }

        #[#rocket::async_trait]
        impl<'r> #rocket::request::FromRequest<'r> for &'r #name {
            type Error = #krate::JwtGuardError;

            async fn from_request(request: &'r #rocket::request::Request<'_>) -> #rocket::request::Outcome<Self, Self::Error> {
                // The result is cached in the request, so several guards in the same route only verify the token once.
                let result: &::core::result::Result<#name, #krate::JwtGuardError> = request.local_cache(|| {
                    <#name as #krate::FromJwtRequest>::from_jwt_request(request)
                });

                #record_challenge

                match result {
                    ::core::result::Result::Ok(claims) => #rocket::outcome::Outcome::Success(claims),
                    #cached_error_arm
                }
            }
        }
    };

    Ok(quote! {
        #jwt_impl

        #jwt_cookie_impl

        #jwt_challenge_impl

        #from_jwt_request_impl

        #from_request_impl
    })
}
