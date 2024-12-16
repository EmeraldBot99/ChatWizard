pub mod crypto;
pub mod state;
use crypto::cipher::Cipher;
use crypto::KeyPair;


fn main() {
    let key: Vec<u8> = KeyPair::KeyPair::generate().private_key;
    let message = b"super secret message";
    
    // Encrypt the message
    let (ciphertext, nonce) = Cipher::encrypt(message, &key).expect("test");

    // Decrypt the message
    let decrypted_message = Cipher::decrypt(&ciphertext, &key, &nonce).expect("test");

    assert_eq!(message.to_vec(), decrypted_message);

    println!("{:?}", ciphertext);
    println!("{:?}", String::from_utf8(decrypted_message).expect("failed to convert to utf-8"));


}
