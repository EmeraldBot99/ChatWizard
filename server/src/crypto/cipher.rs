use rand_core::OsRng;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, Tag};
use aes_gcm::aead::Aead;
use rand_core::RngCore;
pub struct cipher;

impl cipher {
    pub fn encrypt(message:&[u8],key:&[u8]) -> Vec<u8>{
        let key = Key::from_slice(key);

        let encrypt_cipher = Aes256Gcm::new(key);

        //create a nonce (random value only used once)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        encrypt_cipher.encrypt(nonce, message).expect("encryption failed")
    }
}