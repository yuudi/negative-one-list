use actix_web::{get, web::Data, App, HttpRequest, HttpResponse, HttpServer, Responder};
use config::Config;
use env_logger;
use serde::Deserialize;
use std::{default, error, sync::Arc};

use crate::oauth2::Client;
mod oauth2;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

fn create_client(conf: Conf) -> Result<oauth2::Client> {
    let (auth_url, token_url) = match conf.location.as_str() {
        "global" | "us" => (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        ),
        "cn" => (
            "https://login.partner.microsoftonline.cn/common/oauth2/v2.0/authorize",
            "https://login.partner.microsoftonline.cn/common/oauth2/v2.0/token",
        ),
        "de" => (
            "https://login.microsoftonline.de/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.de/common/oauth2/v2.0/token",
        ),
        "usgov" | "gov" => (
            "https://login.microsoftonline.us/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.us/common/oauth2/v2.0/token",
        ),
        unknown => return Err(format!("Unknown location: {}", unknown).into()),
    };
    let client = oauth2::Client::new(
        conf.client_id,
        conf.client_secret,
        auth_url.to_string(),
        token_url.to_string(),
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
    location: String,
    redirect_url: String,
    refresh_token: String,
    drive_id: String,
    share_root: String,
}

struct AppConf {
    api_root: String,
    share_root: String,
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
async fn listing(req: HttpRequest, data: Data<(Client, AppConf)>) -> impl Responder {
    let (client, app_conf) = data.get_ref();
    let uri = req.match_info().get("uri").unwrap_or("");
    let access_token_result = client.get_access_token().await;
    if let Err(e) = access_token_result {
        let mut body = String::from(HTML_BEFORE);
        body.push_str(e.to_string().as_str());
        body.push_str(HTML_AFTER);
        return HttpResponse::InternalServerError().body(body);
    }
    match get_item(
        &client.drive_id,
        &app_conf.api_root,
        &app_conf.share_root,
        uri,
        &access_token_result.unwrap(),
    )
    .await
    {
        Err(e) => {
            let mut body = String::from(HTML_BEFORE);
            body.push_str(e.to_string().as_str());
            body.push_str(HTML_AFTER);
            HttpResponse::InternalServerError().body(body)
        }
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

async fn get_item(
    drive_id: &str,
    api_root: &str,
    root: &str,
    path: &str,
    token: &str,
) -> Result<DriveItem> {
    if path.is_empty() {
        get_folder(drive_id, api_root, root, path, token).await
    } else if path.ends_with('/') {
        // trim trailing slash because microsoft graph api doesn't like it
        let path = &path[..path.len() - 1];
        get_folder(drive_id, api_root, root, path, token).await
    } else {
        get_file(drive_id, api_root, root, path, token).await
    }
}

async fn get_file(
    drive_id: &str,
    api_root: &str,
    root: &str,
    path: &str,
    token: &str,
) -> Result<DriveItem> {
    let reqwest_client = reqwest::Client::new();
    let response = reqwest_client
        .get(format!(
            "{}/drives/{}/root:/{}{}",
            api_root, drive_id, root, path
        ))
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
    let content_url_value = &json["@microsoft.graph.downloadUrl"];
    if !content_url_value.is_string() {
        return Err("Not a file".into());
    }
    let content_url = content_url_value.as_str().unwrap().to_string();
    Ok(DriveItem::File { name, content_url })
}

async fn get_folder(
    drive_id: &str,
    api_root: &str,
    root: &str,
    path: &str,
    token: &str,
) -> Result<DriveItem> {
    let reqwest_client = reqwest::Client::new();
    let response = reqwest_client
        .get(if path.is_empty() {
            if root.is_empty() {
                format!("{}/drives/{}/root/children", api_root, drive_id)
            } else {
                let root_trimmed = &root[..root.len() - 1];
                format!(
                    "{}/drives/{}/root:/{}:/children",
                    api_root, drive_id, root_trimmed
                )
            }
        } else {
            format!(
                "{}/drives/{}/root:/{}{}:/children",
                api_root, drive_id, root, path
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
    Ok(DriveItem::Folder {
        name: path.to_string(),
        children: Some(children),
    })
}

fn normalize_root_path(path: &str) -> String {
    // normalize path
    // path should prepend to the uri
    // and should not start with a slash and should end with a slash

    let mut path = path.to_owned();
    if path.is_empty() {
        return path;
    }

    // trim ending slash if present
    if !path.ends_with('/') {
        path.push('/');
    }

    // trim leading slash if present
    if path.starts_with('/') {
        path = path[1..].to_string();
    };
    path
}

fn init_client() -> Result<(Client, AppConf)> {
    let settings = Config::builder()
        .add_source(config::File::with_name("config.json"))
        .build()?;
    let conf = settings.try_deserialize::<Conf>()?;

    let api_root = match conf.location.as_str() {
        "global" | "us" => "https://graph.microsoft.com/v1.0",
        "cn" => "https://microsoftgraph.chinacloudapi.cn/v1.0",
        "de" => "https://graph.microsoft.de/v1.0",
        "usgov" | "gov" => "https://graph.microsoft.us/v1.0",
        unknown => return Err(format!("Unknown location: {}", unknown).into()),
    };
    let app_conf = AppConf {
        share_root: normalize_root_path(&conf.share_root),
        api_root: api_root.to_owned(),
    };
    let client = create_client(conf)?;

    Ok((client, app_conf))
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
