use std::error::Error;
use std::fmt::{self, Display};
use std::io::{Read, Write};

pub mod token_store;

pub fn write_to_stream<T: Write>(stream: &mut T, command: &str) -> Result<(), Box<dyn Error>> {
    stream.write_all(dbg!(command).as_bytes())?;
    stream.flush()?;
    Ok(())
}

pub fn read_from_stream<T: Read>(stream: &mut T) -> Result<String, Box<dyn Error>> {
    let mut read_bytes = Vec::new();
    let mut buf = [0; 4096];
    let mut len = 4096;
    while len == 4096 {
        len = stream.read(&mut buf)?;
        read_bytes.extend_from_slice(&buf[..len]);
    }
    Ok(dbg!(String::from_utf8_lossy(&read_bytes).to_string()))
}

#[derive(Debug)]
pub struct MfProxyError {
    pub message: String,
}

impl Display for MfProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MfProxyError: {}", self.message)
    }
}

impl Error for MfProxyError {}
