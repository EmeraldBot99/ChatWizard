use rand_core::OsRng;
use k256::ecdsa::{SigningKey, VerifyingKey};

pub struct KeyPair{
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,


}    
impl KeyPair {
    pub fn generate() -> Self{
        //Generate private key using a random number
        let private_key = SigningKey::random(&mut OsRng);
        //Derive public key from private key
        let public_key = VerifyingKey::from(&private_key);

        //Serialize keys to vec of bytes
        let private_key_bytes = private_key.to_bytes().to_vec();
        let public_key_bytes = public_key.to_encoded_point(true).as_bytes().to_vec();

        //Return key pair object
        KeyPair { private_key: private_key_bytes, public_key: public_key_bytes }
    }

}

