use crate::{
    config::Server, read_from_stream, token_store::UserTokens, verify_password, write_to_stream,
    MfProxyError,
};

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use base64;
use native_tls::TlsConnector;

pub fn smtp_listener(
    server: Server,
    token_store: Arc<Mutex<Option<UserTokens>>>,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("0.0.0.0", server.local_smtp_port))?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let t = Arc::clone(&token_store);
                let cloned = server.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_smtp(cloned, t, stream) {
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

fn handle_smtp(
    server: Server,
    token_store: Arc<Mutex<Option<UserTokens>>>,
    mut in_stream: TcpStream,
) -> Result<(), Box<dyn Error>> {
    let mut out_stream =
        TcpStream::connect((server.remote_smtp_host.clone(), server.remote_smtp_port))?;

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
    let mut out_stream = connector.connect(&server.remote_smtp_host, out_stream)?;
    write_to_stream(&mut out_stream, &ehlo)?;
    let response = read_from_stream(&mut out_stream)?;
    write_to_stream(&mut in_stream, &response)?;
    let next_command = dbg!(read_from_stream(&mut in_stream)?);
    match next_command.as_str() {
        "AUTH LOGIN\r\n" => {
            write_to_stream(&mut in_stream, "334 VXNlcm5hbWU6\r\n")?;
            let username = String::from_utf8_lossy(&base64::decode(
                read_from_stream(&mut in_stream)?.as_bytes(),
            )?)
            .into_owned();
            write_to_stream(&mut in_stream, "334 UGFzc3dvcmQ6\r\n")?;
            let password = String::from_utf8_lossy(&base64::decode(
                read_from_stream(&mut in_stream)?.as_bytes(),
            )?)
            .into_owned();
            if server
                .accounts
                .get(&username)
                .map_or(false, |a| verify_password(&a.psk_argon2id, &password))
            {
                let mut tokens = token_store.lock().map_err(|e| MfProxyError {
                    message: format!("Couldn't lock mutex for token store during SMTP ({:?})", e),
                })?;
                write_to_stream(
                    &mut out_stream,
                    &format!(
                        "AUTH XOAUTH2 {}\r\n",
                        tokens
                            .as_mut()
                            .ok_or(MfProxyError {
                                message: "Attempting to do SMTP without a token".to_owned(),
                            })?
                            .encoded_access_token()?
                    ),
                )?;
            } else {
                return Err(Box::new(MfProxyError {
                    message: "Failed to verify username with password".to_owned(),
                }));
            }
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
