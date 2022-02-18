use crate::token_store::UserTokens;

use std::error::Error;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Response, Server};
use url::Url;

fn response_for_callback(
    url: Url,
    token_store: &Arc<Mutex<Option<UserTokens>>>,
) -> Response<Cursor<Vec<u8>>> {
    url.query_pairs()
        .find(|(k, _v)| k == "code")
        .ok_or_else(|| Response::from_string("couldn't find code parameter").with_status_code(400))
        .and_then(|(_k, code)| {
            let mut tokens = token_store.lock().map_err(|e| {
                eprintln!("{:?}", e);
                Response::from_string("couldn't lock mutex to request tokens, see logs")
                    .with_status_code(500)
            })?;
            Ok(match UserTokens::authorize(code.to_string()) {
                Ok(t) => {
                    *tokens = Some(t);
                    Response::from_string("successfully authorized")
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                    Response::from_string("failed to authorize from code, see logs")
                }
            })
        })
        .unwrap_or_else(|e| e)
}

pub fn http_listener(
    token_store: Arc<Mutex<Option<UserTokens>>>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let server = Server::http("127.0.0.1:8000")?;

    let authorize_url: String = Url::parse_with_params("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", [
        ("response_type", "code"),
        ("redirect_uri", "http://localhost:8000/callback"),
        ("client_id", "0b67573a-e1c8-4893-a8a4-180df14dba7a"),
        ("scope", "https://outlook.office365.com/IMAP.AccessAsUser.All https://outlook.office365.com/POP.AccessAsUser.All https://outlook.office365.com/SMTP.Send offline_access"),
    ])?.into();

    for request in server.incoming_requests() {
        if request.url() == "/start" {
            request.respond(Response::empty(303).with_header(
                Header::from_bytes(&b"location"[..], authorize_url.as_bytes()).unwrap(),
            ))?;
        } else if request.url().starts_with("/callback?") {
            let url = Url::parse(&("http://empty".to_owned() + request.url()))?;
            request.respond(response_for_callback(url, &token_store))?;
        } else {
            request.respond(Response::empty(404))?;
        }
    }
    Ok(())
}
