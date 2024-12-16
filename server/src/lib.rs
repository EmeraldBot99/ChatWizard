pub mod crypto;


#[cfg(test)]
mod tests {
    use crate::crypto::{cipher::Cipher, KeyPair::KeyPair};


    #[test]
    fn test_encryption(){
        let key: Vec<u8> = KeyPair::generate().private_key;
        let message = b"super secret message";
        
        let (ciphertext, nonce) = Cipher::encrypt(message, &key).expect("encryption failed");
    
        let decrypted_message = Cipher::decrypt(&ciphertext, &key, &nonce).expect("decryption failed");
    
        assert_eq!(message.to_vec(), decrypted_message);
    }
}