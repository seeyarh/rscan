use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::read_to_string;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct Handshake {
    pub service: String,
    pub request: String,
    pub response: String,
}

pub fn get_service_handshakes(handshakes_file: &str) -> Result<Vec<Handshake>, Box<dyn Error>> {
    let s = read_to_string(handshakes_file)?;
    let handshakes: Vec<Handshake> = serde_yaml::from_str(&s)?;
    Ok(handshakes)
}
