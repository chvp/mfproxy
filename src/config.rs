use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use toml;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub http_port: u16,
    pub base_redirect_uri: String,
    pub servers: HashMap<String, Server>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Server {
    pub authorize_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub local_smtp_port: u16,
    pub local_imap_port: u16,
    pub remote_smtp_host: String,
    pub remote_imap_host: String,
    pub remote_smtp_port: u16,
    pub remote_imap_port: u16,
    pub remote_smtp_starttls: bool,
    pub remote_imap_starttls: bool,
    pub accounts: HashMap<String, Account>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Account {
    pub psk_argon2id: String,
    pub username: String,
    pub reminder_days: usize,
    pub nag_timer_days: usize,
}

impl Config {
    pub fn read(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        Ok(toml::from_str(&fs::read_to_string(&path)?)?)
    }
}
