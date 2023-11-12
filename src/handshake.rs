use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::read_to_string;

use base64::{engine::general_purpose, Engine as _};

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct HandshakeDefinition {
    pub service: String,
    pub request: String,
    pub response: String,
}

impl HandshakeDefinition {
    fn to_handshake(self) -> Handshake {
        Handshake {
            service: self.service,
            request: general_purpose::STANDARD
                .decode(self.request)
                .expect("failed to decode handshake"),
            response: general_purpose::STANDARD
                .decode(self.response)
                .expect("failed to decode handshake"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct Handshake {
    pub service: String,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

pub fn get_service_handshakes(handshakes_file: &str) -> Result<Vec<Handshake>, Box<dyn Error>> {
    let s = read_to_string(handshakes_file)?;
    let handshake_defs: Vec<HandshakeDefinition> = serde_yaml::from_str(&s)?;
    let handshakes = handshake_defs
        .into_iter()
        .map(|h| h.to_handshake())
        .collect();
    Ok(handshakes)
}
