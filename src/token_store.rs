use base64;
use chrono::{DateTime, Duration, Utc};
use reqwest::{blocking::Client, StatusCode};
use serde::Deserialize;
use std::error::Error;

use crate::MfProxyError;

#[derive(Debug)]
pub struct UserTokens {
    pub creation_time: DateTime<Utc>,
    pub refresh_token: String,
    pub access_token: String,
    pub expiration: DateTime<Utc>,
    pub nag_counter: usize,
}

impl UserTokens {
    pub fn authorize(code: String) -> Result<Self, Box<dyn Error>> {
        let response = request_tokens(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            &[
                ("grant_type", "authorization_code"),
                ("redirect_uri", "http://localhost:8000/callback"),
                ("client_id", "0b67573a-e1c8-4893-a8a4-180df14dba7a"),
                ("client_secret", "HhD7Q~t4ihAdWbb5Kt8MTIQYgBqt8RiJ9HqVb"),
                ("code", code.as_str()),
            ],
        )?;
        Ok(Self {
            creation_time: Utc::now(),
            refresh_token: response.refresh_token,
            access_token: response.access_token,
            expiration: Utc::now() + Duration::seconds(response.expires_in),
            nag_counter: 0,
        })
    }

    pub fn encoded_access_token(&mut self) -> Result<String, Box<dyn Error>> {
        if self.access_token_expired() {
            self.refresh_token()?;
        }
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(b"user=charlotte.vanpetegem@ugent.be");
        data.push(10);
        data.extend_from_slice(b"auth=Bearer ");
        data.extend_from_slice(self.access_token.as_bytes());
        data.extend_from_slice(&[10, 10]);
        Ok(base64::encode(&data))
    }

    fn access_token_expired(&self) -> bool {
        self.expiration < Utc::now()
    }

    fn refresh_token(&mut self) -> Result<(), Box<dyn Error>> {
        let response = request_tokens(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", "0b67573a-e1c8-4893-a8a4-180df14dba7a"),
                ("client_secret", "HhD7Q~t4ihAdWbb5Kt8MTIQYgBqt8RiJ9HqVb"),
                ("code", self.refresh_token.clone().as_str()),
            ],
        )?;
        self.refresh_token = response.refresh_token;
        self.access_token = response.access_token;
        self.expiration = Utc::now() + Duration::seconds(response.expires_in);
        Ok(())
    }
}

fn request_tokens(uri: &str, params: &[(&str, &str)]) -> Result<TokenResponse, Box<dyn Error>> {
    let client = Client::new();
    let resp = client.post(uri).form(params).send()?;

    match resp.status() {
        StatusCode::OK => Ok(resp.json()?),
        _ => Err(Box::new(MfProxyError {
            message: format!("failed to get access and refresh token ({})", resp.text()?),
        })),
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}
