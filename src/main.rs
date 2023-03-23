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
        conf.drive_id,
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
    drive_id: String,
}

enum DriveItem {
    File {
        name: String,
        content_url: String,
    },
    Folder {
        name: String,
        children: Option<Vec<DriveItem>>,
    },
}

const HTML_BEFORE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Document</title>
<link rel="shortcut icon" href="data:;">
</head>
<body>"#;

const HTML_AFTER: &str = r#"</body>
</html>"#;

#[get("/{uri:.*}")]
async fn listing(req: HttpRequest, client: Data<Client>) -> impl Responder {
    let uri = req.match_info().get("uri").unwrap_or("");
    let access_token = client.get_access_token().await;
    match get_item(&client.drive_id, uri, &access_token.unwrap()).await {
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        Ok(DriveItem::File { name, content_url }) => HttpResponse::Found()
            .insert_header(("Location", content_url))
            .finish(),
        Ok(DriveItem::Folder {
            name,
            children: None,
        }) => HttpResponse::Ok().body(name),
        Ok(DriveItem::Folder {
            name,
            children: Some(children),
        }) => {
            let mut body = String::from(HTML_BEFORE);
            body.push_str(&format!("<h1>{}</h1>", name));
            for child in children {
                match child {
                    DriveItem::File { name, content_url } => {
                        body.push_str(&format!(
                            r#"<a href="{}" download>{}</a><br/>"#,
                            content_url, name
                        ));
                    }
                    DriveItem::Folder { name, children } => {
                        body.push_str(&format!(r#"<a href="./{}/">{}/</a><br/>"#, name, name));
                    }
                }
            }
            body.push_str(HTML_AFTER);
            HttpResponse::Ok().body(body)
        }
    }
}

async fn get_item(drive_id: &str, path: &str, token: &str) -> Result<DriveItem> {
    let reqwest_client = reqwest::Client::new();
    let response = reqwest_client
        .get(if path.is_empty() {
            format!("https://graph.microsoft.com/v1.0/drives/{}/root", drive_id)
        } else {
            format!(
                "https://graph.microsoft.com/v1.0/drives/{}/root:/{}",
                drive_id, path
            )
        })
        .bearer_auth(token)
        .send()
        .await?;

    if !response.status().is_success() {
        return if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err("404 Not found".into())
        } else {
            Err(format!("Error: {}", response.status()).into())
        };
    }

    let json: serde_json::Value = response.json().await?;
    let name = json["name"].as_str().unwrap().to_string();
    if json["folder"].is_null() {
        let content_url = json["@microsoft.graph.downloadUrl"]
            .as_str()
            .unwrap()
            .to_string();
        Ok(DriveItem::File { name, content_url })
    } else {
        let item_id = json["id"].as_str().unwrap();
        let children = get_children(drive_id, item_id, token).await?;
        Ok(DriveItem::Folder {
            name,
            children: Some(children),
        })
    }
}

async fn get_children(drive_id: &str, item_id: &str, token: &str) -> Result<Vec<DriveItem>> {
    let reqwest_client = reqwest::Client::new();
    let response = reqwest_client
        .get(format!(
            "https://graph.microsoft.com/v1.0/drives/{}/items/{}/children",
            drive_id, item_id
        ))
        .bearer_auth(token)
        .send()
        .await?;
    let json: serde_json::Value = response.json().await?;
    let mut children = Vec::new();
    for item in json["value"].as_array().unwrap() {
        let name = item["name"].as_str().unwrap().to_string();
        if item["folder"].is_null() {
            let content_url = item["@microsoft.graph.downloadUrl"]
                .as_str()
                .unwrap()
                .to_string();
            children.push(DriveItem::File { name, content_url });
        } else {
            children.push(DriveItem::Folder {
                name,
                children: None,
            });
        }
    }
    Ok(children)
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
