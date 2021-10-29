use mfproxy::{read_from_stream, token_store::UserTokens, write_to_stream, MfProxyError};

use native_tls::TlsConnector;
use tiny_http::{Header, Response, Server};
use url::Url;

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

fn smtp_listener(token_store: Arc<Mutex<UserTokens>>) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:1234")?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let t = Arc::clone(&token_store);
                thread::spawn(move || {
                    if let Err(e) = handle_smtp(t, stream) {
                        eprintln!("{:?}", e);
                    }
                });
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    Ok(())
}

fn http_listener(
    token_store: Arc<Mutex<UserTokens>>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let server = Server::http("127.0.0.1:8000")?;

    let authorize_url: String = Url::parse_with_params("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", [
        ("response_type", "code"),
        ("redirect_uri", "http://localhost:8000/callback"),
        ("client_id", "<redacted>"),
        ("scope", "https://outlook.office365.com/IMAP.AccessAsUser.All https://outlook.office365.com/POP.AccessAsUser.All https://outlook.office365.com/SMTP.Send offline_access"),
    ])?.into();

    for request in server.incoming_requests() {
        if request.url() == "/start" {
            request.respond(Response::empty(303).with_header(
                Header::from_bytes(&b"location"[..], &authorize_url.as_bytes()[..]).unwrap(),
            ))?;
        } else if request.url().starts_with("/callback?") {
            let url = Url::parse(&("http://empty".to_owned() + request.url()))?;
            if let Some((_, code)) = url.query_pairs().find(|(k, _v)| k == "code") {
                match token_store.lock() {
                    Ok(mut tokens) => match tokens.authorize(code.to_string()) {
                        Ok(()) => {
                            request.respond(Response::from_string("successfully authorized"))?
                        }
                        Err(e) => {
                            request.respond(
                                Response::from_string("failed to authorize from code, see logs")
                                    .with_status_code(400),
                            )?;
                            eprintln!("{:?}", e);
                        }
                    },
                    Err(e) => {
                        request.respond(
                            Response::from_string("couldn't lock mutex, see logs")
                                .with_status_code(500),
                        )?;
                        eprintln!("{:?}", e);
                    }
                };
            } else {
                request.respond(
                    Response::from_string("couldn't find code parameter").with_status_code(400),
                )?;
            }
        } else {
            request.respond(Response::empty(404))?;
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let token_store = Arc::new(Mutex::new(UserTokens::new()));
    let barrier = Arc::new(Barrier::new(2));

    let b = Arc::clone(&barrier);
    let t = Arc::clone(&token_store);
    thread::spawn(move || {
        if let Err(e) = http_listener(t) {
            eprintln!("Error creating http listener: {:?}", e);
        }
        b.wait();
    });
    let b = Arc::clone(&barrier);
    let t = Arc::clone(&token_store);
    thread::spawn(move || {
        if let Err(e) = smtp_listener(t) {
            eprintln!("Error creating smtp listener: {:?}", e);
        }
        b.wait();
    });

    barrier.wait();

    Ok(())
}

fn handle_smtp(
    token_store: Arc<Mutex<UserTokens>>,
    mut in_stream: TcpStream,
) -> Result<(), Box<dyn Error>> {
    let mut out_stream = TcpStream::connect("smtp.office365.com:587")?;

    write_to_stream(&mut in_stream, &read_from_stream(&mut out_stream)?)?;
    // First EHLO
    let ehlo = read_from_stream(&mut in_stream)?;
    write_to_stream(&mut out_stream, &ehlo)?;
    // Discard response, we want to send back the response of the EHLO after the STARTTLS
    dbg!(read_from_stream(&mut out_stream)?);
    write_to_stream(&mut out_stream, "STARTTLS\r\n")?;
    // Assume the peer wants to STARTTLS
    dbg!(read_from_stream(&mut out_stream)?);

    let connector = TlsConnector::builder().build()?;
    let mut out_stream = connector.connect("smtp.office365.com", out_stream)?;
    write_to_stream(&mut out_stream, &ehlo)?;
    let response = read_from_stream(&mut out_stream)?;
    write_to_stream(&mut in_stream, &response)?;
    let next_command = dbg!(read_from_stream(&mut in_stream)?);
    match next_command.as_str() {
        "AUTH LOGIN\r\n" => {
            write_to_stream(&mut in_stream, "334 VXNlcm5hbWU6\r\n")?;
            let _username = read_from_stream(&mut in_stream)?;
            write_to_stream(&mut in_stream, "334 UGFzc3dvcmQ6\r\n")?;
            let _password = read_from_stream(&mut in_stream)?;
            match token_store.lock() {
                Ok(mut tokens) => {
                    write_to_stream(
                        &mut out_stream,
                        &format!("AUTH XOAUTH2 {}\r\n", tokens.encoded_access_token()?),
                    )?;
                }
                Err(e) => {
                    return Err(Box::new(MfProxyError {
                        message: format!(
                            "Couldn't lock mutex for token store during SMTP ({:?})",
                            e
                        ),
                    }));
                }
            };
        }
        _ => unreachable!(),
    };
    // Report authentication results
    write_to_stream(&mut in_stream, &read_from_stream(&mut out_stream)?)?;

    in_stream.set_nonblocking(true)?;
    out_stream.get_mut().set_nonblocking(true)?;

    let mut buf = [0; 1024];
    loop {
        match in_stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out_stream.write_all(&buf[..n])?,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                return Err(e.into());
            }
        }
        match out_stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => in_stream.write_all(&buf[..n])?,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    Ok(())
}
