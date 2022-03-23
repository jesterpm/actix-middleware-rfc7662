//! Actix-web extractor which validates OAuth2 tokens through an
//! [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) token
//! introspection endpoint.
//!
//! To protect a resource, you add the `RequireAuthorization` extractor.
//! This extractor must be configured with a token introspection url
//! before it can be used.
//!
//! The extractor takes an implementation of the
//! `AuthorizationRequirements` trait, which is used to analyze the
//! introspection response to determine if the request is authorized.
//!
//! # Example
//! ```
//! # use std::future::Future;
//! # use actix_web::{ get, HttpResponse, HttpServer, Responder };
//! # use actix_middleware_rfc7662::{AnyScope, RequireAuthorization, RequireAuthorizationConfig, StandardToken};
//!
//! #[get("/protected/api")]
//! async fn handle_read(_auth: RequireAuthorization<AnyScope>) -> impl Responder {
//!     HttpResponse::Ok().body("Success!\n")
//! }
//!
//! fn setup_server() -> std::io::Result<impl Future> {
//!     let oauth_config = RequireAuthorizationConfig::<StandardToken>::new(
//!         "client_id".to_string(),
//!         Some("client_secret".to_string()),
//!         "https://example.com/oauth/authorize".parse().expect("invalid url"),
//!         "https://example.com/oauth/introspect".parse().expect("invalid url"),
//!     );
//!
//!     Ok(HttpServer::new(move || {
//!         actix_web::App::new()
//!             .app_data(oauth_config.clone())
//!             .service(handle_read)
//!     })
//!     .bind("127.0.0.1:8182".to_string())?
//!     .run())
//! }
//! ```

use actix_web::{dev, FromRequest, HttpRequest};
use futures_util::future::LocalBoxFuture;
use oauth2::basic::BasicErrorResponseType;
use oauth2::url::Url;
use oauth2::{
    reqwest, AccessToken, AuthUrl, ClientId, ClientSecret, IntrospectionUrl, StandardErrorResponse,
    StandardRevocableToken, StandardTokenResponse, TokenIntrospectionResponse,
};
use std::future::ready;
use std::marker::PhantomData;
use std::sync::Arc;

// Re-exports
pub use oauth2::{
    basic::BasicTokenType, EmptyExtraTokenFields as StandardToken, ExtraTokenFields,
    StandardTokenIntrospectionResponse,
};

mod error;

#[cfg(feature = "indieauth")]
pub mod indieauth;

pub use error::Error;

const BEARER_TOKEN_PREFIX: &str = "Bearer ";

pub type IntrospectionResponse<T> = StandardTokenIntrospectionResponse<T, BasicTokenType>;

pub trait AuthorizationRequirements<T>
where
    T: ExtraTokenFields,
{
    fn authorized(introspection: &IntrospectionResponse<T>) -> Result<bool, Error>;
}

pub trait RequireScope {
    fn scope() -> &'static str;
}

impl<T, S> AuthorizationRequirements<T> for S
where
    S: RequireScope,
    T: ExtraTokenFields,
{
    fn authorized(introspection: &IntrospectionResponse<T>) -> Result<bool, Error> {
        Ok(introspection
            .scopes()
            .map(|s| s.iter().find(|s| s.as_ref() == S::scope()).is_some())
            .unwrap_or(false))
    }
}

pub struct AnyScope;

impl<T> AuthorizationRequirements<T> for AnyScope
where
    T: ExtraTokenFields,
{
    fn authorized(_: &IntrospectionResponse<T>) -> Result<bool, Error> {
        Ok(true)
    }
}

pub struct RequireAuthorization<R, T = StandardToken>
where
    R: AuthorizationRequirements<T>,
    T: ExtraTokenFields,
{
    introspection: IntrospectionResponse<T>,
    _auth_marker: PhantomData<R>,
}

impl<R, T> RequireAuthorization<R, T>
where
    R: AuthorizationRequirements<T>,
    T: ExtraTokenFields,
{
    pub fn introspection(&self) -> &IntrospectionResponse<T> {
        &self.introspection
    }
}

impl<R, T> FromRequest for RequireAuthorization<R, T>
where
    R: AuthorizationRequirements<T> + 'static,
    T: ExtraTokenFields + 'static + Clone,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut dev::Payload) -> Self::Future {
        let my_req2 = req.clone();

        let verifier = if let Some(verifier) = my_req2.app_data::<RequireAuthorizationConfig<T>>() {
            verifier.clone()
        } else {
            return Box::pin(ready(Err(Error::ConfigurationError)));
        };

        let my_req = req.clone();

        Box::pin(async move {
            verifier
                .verify_request(my_req)
                .await
                .and_then(|introspection| {
                    if R::authorized(&introspection)? {
                        Ok(RequireAuthorization {
                            introspection,
                            _auth_marker: PhantomData::default(),
                        })
                    } else {
                        Err(Error::AccessDenied)
                    }
                })
        })
    }
}

#[derive(Clone)]
struct RequireAuthorizationConfigInner<T>
where
    T: ExtraTokenFields,
{
    client: oauth2::Client<
        StandardErrorResponse<BasicErrorResponseType>,
        StandardTokenResponse<T, BasicTokenType>,
        BasicTokenType,
        StandardTokenIntrospectionResponse<T, BasicTokenType>,
        StandardRevocableToken,
        StandardErrorResponse<BasicErrorResponseType>,
    >,
}

#[derive(Clone)]
pub struct RequireAuthorizationConfig<T>(Arc<RequireAuthorizationConfigInner<T>>)
where
    T: ExtraTokenFields;

impl<T> RequireAuthorizationConfig<T>
where
    T: ExtraTokenFields,
{
    pub fn new(
        client_id: String,
        client_secret: Option<String>,
        auth_url: Url,
        introspection_url: Url,
    ) -> Self {
        let client = oauth2::Client::new(
            ClientId::new(client_id),
            client_secret.map(|s| ClientSecret::new(s)),
            AuthUrl::from_url(auth_url),
            None,
        )
        .set_introspection_uri(IntrospectionUrl::from_url(introspection_url));
        RequireAuthorizationConfig(Arc::new(RequireAuthorizationConfigInner { client }))
    }

    async fn verify_request(&self, req: HttpRequest) -> Result<IntrospectionResponse<T>, Error> {
        let access_token = req
            .headers()
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.starts_with(BEARER_TOKEN_PREFIX))
            .map(|value| AccessToken::new(value.split_at(BEARER_TOKEN_PREFIX.len()).1.to_string()))
            .ok_or(Error::MissingToken)?;

        self.0
            .client
            .introspect(&access_token)
            .map_err(|e| {
                log::error!("OAuth2 client configuration error: {}", e);
                Error::ConfigurationError
            })?
            .request_async(reqwest::async_http_client)
            .await
            .map_err(|e| {
                log::warn!("Error from token introspection service: {}", e);
                Error::IntrospectionServerError
            })
            .and_then(|resp| {
                if resp.active() {
                    Ok(resp)
                } else {
                    Err(Error::InvalidToken)
                }
            })
    }
}
