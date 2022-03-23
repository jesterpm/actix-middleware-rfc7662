//! Extras for working with IndieAuth endpoints.

use oauth2::ExtraTokenFields;
use serde::{Deserialize, Serialize};

/// An IndieAuth access token and introspection reponse has an additional
/// `me` field.
///
/// See https://indieauth.spec.indieweb.org/#access-token-verification
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IndieAuthToken {
    me: String,
}

impl IndieAuthToken {
    pub fn me(&self) -> &str {
        &self.me
    }
}

impl ExtraTokenFields for IndieAuthToken {}
