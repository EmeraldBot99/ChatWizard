use rand_core::OsRng;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Error};
use rand_core::RngCore;

pub struct Cipher;

impl Cipher {
    pub fn encrypt(message:&[u8],key:&[u8]) ->  Result<(Vec<u8>, Vec<u8>), Error>{

        //convert key to vec of bytes
        let key = Key::<Aes256Gcm>::from_slice(key);

        let encrypt_cipher = Aes256Gcm::new(key);

        //create a nonce (random value only used once)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        //encrypt message
        let ciphertext = encrypt_cipher.encrypt(nonce, message)?;

        //return nonce with ciphertext, or error if fails
        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    pub fn decrypt(message: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
        //convert key to vec of bytes
        let key = Key::<Aes256Gcm>::from_slice(key);
        
        let encrypt_cipher = Aes256Gcm::new(key);
        
        let nonce = Nonce::from_slice(nonce);
        encrypt_cipher.decrypt(nonce, message)
    }
}