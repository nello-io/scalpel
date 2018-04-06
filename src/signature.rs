use bytes::Bytes;
use untrusted;

use ring;
use ring::{rand, signature};

pub struct Signature {
    pub keypair: Option<signature::Ed25519KeyPair>, 
}


impl Signature {

    pub fn new() -> Self {
        Self{   keypair: Signature::generate_ed25519_keypair(), }
    }
    
    /// generate a ed25519 keypair in pkcs8 format
    fn generate_ed25519_keypair() -> Option<signature::Ed25519KeyPair> {

        let rng = rand::SystemRandom::new();
        let bytes =  match signature::Ed25519KeyPair::generate_pkcs8(&rng) {
            Ok(byt) => byt,
            Err(_)  => return None,
        };
        let input = untrusted::Input::from(&bytes);
        match signature::Ed25519KeyPair::from_pkcs8(input){
            Ok(key) => Some(key),
            Err(_)  => None,
        }
    }

    /// sign file with generated keypair
    pub fn sign_file(key_pair: signature::Ed25519KeyPair, file: &Bytes)
                        -> ring::signature::Signature {
        
        key_pair.sign(&file)
                
    }
    
}