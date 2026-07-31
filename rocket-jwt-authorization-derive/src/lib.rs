/*!
# `jwt-authorization` Request Guard for Rocket Framework

This crate provides the `JWT` derive macro of the [`rocket-jwt-authorization`](https://crates.io/crates/rocket-jwt-authorization) crate.

Use `rocket-jwt-authorization` instead of depending on this crate directly.
*/

mod attribute;
mod generate;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Creates request guards which read a JWT from a request and verify it.
///
/// See the documentation of the `rocket-jwt-authorization` crate for the options of the `jwt` attribute.
#[proc_macro_derive(JWT, attributes(jwt))]
pub fn jwt_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    match generate::expand(ast) {
        Ok(token_stream) => token_stream.into(),
        Err(error) => error.to_compile_error().into(),
    }
}
