use hmac::{Hmac, Mac};
use sha2::Sha256;

// Define an alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("Error genererate_hmac");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(key: &[u8], data: &[u8], hmac_to_verify: &[u8]) -> bool {
    let mac = HmacSha256::new_from_slice(key).expect("Error verify_hmac");
    mac.verify_slice(hmac_to_verify).is_ok()
}