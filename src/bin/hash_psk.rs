use std::error::Error;
use std::io;

use argon2::{password_hash::{rand_core::OsRng, SaltString, PasswordHasher}, Argon2};

fn main() -> Result<(), Box<dyn Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let stdin = io::stdin();
    let mut buffer = String::new();
    stdin.read_line(&mut buffer)?;
    let _newline = buffer.pop();

    println!("{}", argon2.hash_password(buffer.as_bytes(), &salt).expect("failed to hash password").to_string());
    Ok(())
}
