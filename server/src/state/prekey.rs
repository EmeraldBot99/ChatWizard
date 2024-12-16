use server::crypto::KeyPair::KeyPair;
use std::error::Error;

pub struct PreKey {
    pub id: u32,
    pub public_key: Vec<u8>,
}

pub fn generate_prekeys(num_prekeys: usize) -> Result<Vec<PreKey>, Box<dyn Error>> {
    let mut prekeys = Vec::with_capacity(num_prekeys);

    for id in 1..=num_prekeys {
        let key_pair = KeyPair::generate();
        let public_key = key_pair.public_key;
        prekeys.push(PreKey {
            id: id as u32,
            public_key: public_key,
        });
    }

    Ok(prekeys)
}

//TODO: ADD FUNC TO STORE AND FETCH KEYS FROM SERVER