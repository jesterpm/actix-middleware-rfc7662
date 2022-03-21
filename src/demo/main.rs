use actix_middleware_rfc7662::{
    AnyScope, RequireAuthorization, RequireAuthorizationConfig, RequireScope,
};
use actix_web::{get, HttpResponse, HttpServer, Responder};

#[get("/read")]
async fn handle_read(_auth: RequireAuthorization<AnyScope>) -> impl Responder {
    HttpResponse::Ok().body("Success!\n")
}

struct WriteScope;
impl RequireScope for WriteScope {
    fn scope() -> &'static str {
        "write"
    }
}

#[get("/write")]
async fn handle_write(_auth: RequireAuthorization<WriteScope>) -> impl Responder {
    HttpResponse::Ok().body("Success!\n")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8182".to_string());

    let oauth_config = RequireAuthorizationConfig::new(
        "cid1".to_string(),
        Some("cs1".to_string()),
        "https://cadmium.jesterpm.net/oauth/authorize"
            .parse()
            .expect("invalid url"),
        "https://cadmium.jesterpm.net/oauth/introspect"
            .parse()
            .expect("invalid url"),
    );

    HttpServer::new(move || {
        actix_web::App::new()
            .app_data(oauth_config.clone())
            .service(handle_read)
            .service(handle_write)
    })
    .bind(bind)?
    .run()
    .await
}
