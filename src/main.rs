use native_tls::TlsConnector;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn write_to_stream<T: Write>(stream: &mut T, command: &str) -> Result<(), Box<dyn Error>> {
    stream.write_all(dbg!(command).as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn read_from_stream<T: Read>(stream: &mut T) -> Result<String, Box<dyn Error>> {
    let mut read_bytes = Vec::new();
    let mut buf = [0; 4096];
    let mut len = 4096;
    while len == 4096 {
        len = stream.read(&mut buf)?;
        read_bytes.extend_from_slice(&buf[..len]);
    }
    Ok(dbg!(String::from_utf8_lossy(&read_bytes).to_string()))
}

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:1234")?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_smtp(stream) {
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

fn handle_smtp(mut in_stream: TcpStream) -> Result<(), Box<dyn Error>> {
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
            write_to_stream(&mut out_stream, "AUTH XOAUTH2 <insert token here>\r\n")?;
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
