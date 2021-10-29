use base64;
use chrono::{DateTime, Duration, TimeZone, Utc};
use reqwest::{blocking::Client, StatusCode};
use serde::Deserialize;
use std::error::Error;

use crate::MfProxyError;

#[derive(Debug)]
pub struct UserTokens {
    pub creation_time: Option<DateTime<Utc>>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub expiration: Option<DateTime<Utc>>,
}

impl UserTokens {
    pub fn authorize(&mut self, code: String) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        let resp = client
            .post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
            .form(&[
                ("grant_type", "authorization_code"),
                ("redirect_uri", "http://localhost:8000/callback"),
                ("client_id", "<redacted>"),
                ("client_secret", "<redacted>"),
                ("code", code.as_str()),
            ])
            .send()?;

        match resp.status() {
            StatusCode::OK => {
                let tokens: TokenResponse = resp.json()?;
                self.creation_time = Some(Utc::now());
                self.access_token = Some(tokens.access_token);
                self.refresh_token = Some(tokens.refresh_token);
                self.expiration = Some(Utc::now() + Duration::seconds(tokens.expires_in));
                Ok(())
            }
            _ => Err(Box::new(MfProxyError {
                message: format!("Failed to get access and refresh token ({})", resp.text()?),
            })),
        }
    }

    pub fn encoded_access_token(&mut self) -> Result<String, Box<dyn Error>> {
        if self.access_token_expired() {
            return Err(Box::new(MfProxyError {
                message: "getting a new token isn't implemented yet".to_owned(),
            }));
        }
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice("user=charlotte.vanpetegem@ugent.beauth=Bearer ".as_bytes());
        data.extend_from_slice(
            self.access_token
                .as_ref()
                .ok_or(MfProxyError {
                    message: "not authenticated yet".to_owned(),
                })?
                .as_bytes(),
        );
        data.extend_from_slice("".as_bytes());
        Ok(base64::encode(&data))
    }

    fn access_token_expired(&self) -> bool {
        self.expiration.unwrap_or_else(|| Utc.timestamp(0, 0)) < Utc::now()
    }

    pub fn new() -> UserTokens {
        UserTokens {
            creation_time: None,
            refresh_token: None,
            access_token: None,
            expiration: None,
        }
    }
}

impl Default for UserTokens {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}
