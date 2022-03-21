use actix_web::http::{header, StatusCode};
use actix_web::{HttpResponse, ResponseError};
use std::fmt::{Display, Formatter};

#[derive(Debug, Copy, Clone)]
pub enum Error {
    MissingToken,
    InvalidToken,
    ConfigurationError,
    IntrospectionServerError,
    AccessDenied,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::AccessDenied => "Access denied",
            Error::MissingToken => "Missing authorization token",
            Error::InvalidToken => "Invalid access token",
            Error::ConfigurationError => "OAuth2 client configuration error",
            Error::IntrospectionServerError => "Introspection endpoint returned an error",
        })
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::AccessDenied => StatusCode::FORBIDDEN,
            Error::MissingToken => StatusCode::UNAUTHORIZED,
            Error::InvalidToken => StatusCode::UNAUTHORIZED,
            Error::ConfigurationError => StatusCode::INTERNAL_SERVER_ERROR,
            Error::IntrospectionServerError => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut resp = HttpResponse::build(self.status_code());
        match self {
            Error::AccessDenied => {
                resp.insert_header((header::WWW_AUTHENTICATE, "Bearer"));
                resp.body("{\"error\": \"insufficient_scope\"}")
            }
            Error::MissingToken => resp.finish(),
            Error::InvalidToken => {
                resp.insert_header((header::WWW_AUTHENTICATE, "Bearer"));
                resp.body("{\"error\": \"invalid_token\"}")
            }
            Error::ConfigurationError => resp.finish(),
            Error::IntrospectionServerError => resp.finish(),
        }
    }
}
