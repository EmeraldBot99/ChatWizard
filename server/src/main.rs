pub mod crypto;
use crypto::KeyPair;
use crypto::cipher;

fn main() {
    let test = KeyPair::KeyPair::generate().private_key;

    println!("{:?}", test);
}
