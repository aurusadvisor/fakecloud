//! Re-export of `fakecloud_core::auth_message`.
//!
//! The encoder and decoder live in `fakecloud-core` so the dispatch
//! layer can produce deny tokens inline (the deny decision is computed
//! before any service-specific handler runs). The IAM crate keeps the
//! `crate::auth_message::encode_deny` / `decode_message` paths as
//! re-exports so the STS service code that decodes the token doesn't
//! reach across crate boundaries explicitly.

pub use fakecloud_core::auth_message::{decode_message, encode_deny};
