use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

pub fn generate() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let encoded = STANDARD.encode(key);
    key.zeroize();
    encoded
}
