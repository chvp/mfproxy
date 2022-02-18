use mfproxy::{config::Config, http::http_listener, smtp::smtp_listener};

use std::error::Error;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::read(["config.toml"].iter().collect())?;
    let token_store = Arc::new(Mutex::new(None));
    // If one of the threads fails, stop the program
    let barrier = Arc::new(Barrier::new(2));

    let b = Arc::clone(&barrier);
    let t = Arc::clone(&token_store);
    thread::spawn(move || {
        if let Err(e) = http_listener(t) {
            eprintln!("Error creating http listener: {:?}", e);
        }
        b.wait();
    });
    for (_name, server) in config.servers.iter() {
        let b = Arc::clone(&barrier);
        let t = Arc::clone(&token_store);
        let cloned = server.clone();
        thread::spawn(move || {
            if let Err(e) = smtp_listener(cloned, t) {
                eprintln!("Error creating smtp listener: {:?}", e);
            }
            b.wait();
        });
    }

    barrier.wait();

    Ok(())
}
