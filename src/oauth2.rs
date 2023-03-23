use async_std::sync::RwLock;
use reqwest;
use serde::Deserialize;
use std::error;
use std::time::SystemTime;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;
type Timestamp = u64;
type RefreshToken = String;

pub struct Client {
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    redirect_url: String,
    tokens: RwLock<(AccessToken, RefreshToken)>,
    pub drive_id: String,
}

struct AccessToken {
    access_token: String,
    expires_in: Timestamp,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Timestamp,
    scope: String,
    refresh_token: RefreshToken,
}

impl Client {
    pub fn new(
        client_id: String,
        client_secret: String,
        auth_url: String,
        token_url: String,
        redirect_url: String,
        refresh_token: Option<String>,
        drive_id: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url,
            token_url,
            redirect_url,
            tokens: RwLock::new((
                AccessToken {
                    access_token: String::new(),
                    expires_in: 0,
                },
                refresh_token.unwrap_or(String::new()),
            )),
            drive_id,
        }
    }

    pub async fn get_access_token(&self) -> Result<String> {
        let token = self.tokens.read().await;
        // check token is expired
        if now() < token.0.expires_in {
            Ok(token.0.access_token.clone())
        } else {
            drop(token);  // drop the read lock and acquire a write lock
            let access_token = self.refresh().await?;
            Ok(access_token)
        }
    }

    async fn refresh(&self) -> Result<String> {
        let mut token = self.tokens.write().await;
        // check token is expired again
        if now() < token.0.expires_in {
            return Ok(token.0.access_token.clone());
        }
        let reqwest_client = reqwest::Client::new();
        let resp =  reqwest_client
            .post(self.token_url.as_str())
            .body(format!(
                "client_id={}&client_secret={}&scope=Files.Read&redirect_uri={}&grant_type=refresh_token&refresh_token={}",
                self.client_id,
                self.client_secret,
                self.redirect_url,
                token.1
            ))
            .send()
            .await?
            .json::<TokenResponse>()
            .await?;
        *token = (
            AccessToken {
                access_token: resp.access_token,
                expires_in: now() + resp.expires_in,
            },
            resp.refresh_token,
        );
        Ok(token.0.access_token.clone())
    }
}



fn now() -> Timestamp {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
