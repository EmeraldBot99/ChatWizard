use crate::crypto::KeyPair;

pub struct Identity{
    pub keypair: KeyPair::KeyPair
}
impl Identity{
    pub fn generate() -> Identity{
        Identity { keypair: KeyPair::KeyPair::generate() }
    }
}