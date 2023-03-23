use actix_web::{get, web::Data, App, HttpRequest, HttpResponse, HttpServer, Responder};
use config::Config;
use env_logger;
use serde::Deserialize;
use std::error;

use crate::oauth2::Client;
mod oauth2;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

fn create_client(conf: Conf) -> Result<oauth2::Client> {
    let client = oauth2::Client::new(
        conf.client_id,
        conf.client_secret,
        conf.auth_url,
        conf.token_url,
        conf.redirect_url,
        Some(conf.refresh_token),
    );
    Ok(client)
}

#[derive(Deserialize)]
struct Conf {
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    redirect_url: String,
    refresh_token: String,
}

#[get("/{uri:.*}")]
async fn listing(req: HttpRequest, client: Data<Client>) -> impl Responder {
    let uri = req.match_info().get("uri").unwrap_or("");
    let access_token = client.get_access_token().await;
    HttpResponse::Ok().body(format!("Hello /{}!", uri))
}

fn init_client() -> Result<oauth2::Client> {
    let settings = Config::builder()
        .add_source(config::File::with_name("config.json"))
        .build()?;
    let conf = settings.try_deserialize::<Conf>()?;
    let client = create_client(conf)?;
    Ok(client)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(init_client().unwrap()))
            .service(listing)
    })
    .workers(1)
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
