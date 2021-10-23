use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use std::error::Error;
use native_tls::TlsConnector;

async fn send_command<T: AsyncWrite + Unpin>(stream: &mut T, command: &str) -> Result<(), Box<dyn Error>> {
    stream.write_all(dbg!(command).as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_response<T: AsyncRead + Unpin>(stream: &mut T) -> Result<String, Box<dyn Error>> where T: AsyncRead {
    let mut read_bytes = Vec::new();
    let mut buf = [0; 1024];
    let mut len = 1024;
    while len == 1024 {
        len = stream.read(&mut buf).await?;
        read_bytes.extend_from_slice(&buf[..len]);
    }
    Ok(dbg!(String::from_utf8_lossy(&read_bytes).to_string()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("smtp.office365.com:587").await?;

    print!("{}", read_response(&mut stream).await?);
    send_command(&mut stream, "EHLO client.vanpetegem.me\r\n").await?;
    print!("{}", read_response(&mut stream).await?);
    send_command(&mut stream, "STARTTLS\r\n").await?;
    print!("{}", read_response(&mut stream).await?);

    let connector = tokio_native_tls::TlsConnector::from(TlsConnector::builder().build()?);
    let mut stream = connector.connect("smtp.office365.com", stream).await?;

    send_command(&mut stream, "EHLO client.vanpetegem.me\r\n").await?;
    print!("{}", read_response(&mut stream).await?);

    Ok(())
}
