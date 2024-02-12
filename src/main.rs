use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use clap::Parser;
use std::path::Pathbuf;


enum Direction 
{   Encrypt
,   Decrypt }
    
enum Payload {
    Path(PathBuf),
    Content(String),
}

#[derive(Parser)]
struct Cli {
    key: String,
    direction: Direction,
    path: Payload,
}

fn main() {
    let args = Cli::parse()
}
