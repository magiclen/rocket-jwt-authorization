`jwt-authorization` Request Guard for Rocket Framework
====================

[![CI](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rocket-jwt-authorization/actions/workflows/ci.yml)

This crate provides the `JWT` derive macro of the [rocket-jwt-authorization](https://crates.io/crates/rocket-jwt-authorization) crate.

The generated code needs the traits which live in `rocket-jwt-authorization`, so depend on that crate instead. It re-exports this macro, and its [README](../rocket-jwt-authorization/README.md) documents every option of the `jwt` attribute.

## Crates.io

https://crates.io/crates/rocket-jwt-authorization-derive

## Documentation

https://docs.rs/rocket-jwt-authorization

## License

[MIT](LICENSE)
