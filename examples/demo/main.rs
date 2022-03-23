use actix_middleware_rfc7662::indieauth::IndieAuthToken;
use actix_middleware_rfc7662::{
    AnyScope, RequireAuthorization, RequireAuthorizationConfig, RequireScope,
};
use actix_web::{get, HttpResponse, HttpServer, Responder};

#[get("/read")]
async fn handle_read(auth: RequireAuthorization<AnyScope, IndieAuthToken>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Hello {}!\n",
        auth.introspection().extra_fields().me()
    ))
}

struct WriteScope;
impl RequireScope for WriteScope {
    fn scope() -> &'static str {
        "write"
    }
}

#[get("/write")]
async fn handle_write(_auth: RequireAuthorization<WriteScope, IndieAuthToken>) -> impl Responder {
    HttpResponse::Ok().body("Success!\n")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8182".to_string());

    let oauth_config = RequireAuthorizationConfig::<IndieAuthToken>::new(
        std::env::var("CLIENT_ID").expect("Missing CLIENT_ID"),
        std::env::var("CLIENT_SECRET").ok(),
        std::env::var("AUTH_ENDPOINT")
            .expect("Missing AUTH_ENDPOINT")
            .parse()
            .expect("AUTH_ENDPOINT: invalid url"),
        std::env::var("INTROSPECT_ENDPOINT")
            .expect("Missing INTROSPECT_ENDPOINT")
            .parse()
            .expect("INTROSPECT_ENDPOINT: invalid url"),
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
