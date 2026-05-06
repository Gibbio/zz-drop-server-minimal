#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

//! Minimal reference implementation of the zz-drop API v1.
//!
//! Library crate so the integration tests can build the same `Router`
//! the binary serves, without spinning up a real TCP listener.

pub mod auth;
pub mod config;
pub mod db;
pub mod routes;

pub use config::ServerConfig;
pub use db::Database;
pub use routes::build_router;
