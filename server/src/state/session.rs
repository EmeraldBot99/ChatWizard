use server::crypto::KeyPair::KeyPair;
use super::ratchet::Ratchet;

pub struct Session {
    session_id: String,
    root_key: [u8; 32],
    chain_key: [u8; 32],
    receiving_ratchet: Ratchet, 
    sending_ratchet: Ratchet,
    peer_identity_key: Vec<u8>,
    local_identity_key: KeyPair,
    ephemeral_key: KeyPair,
}