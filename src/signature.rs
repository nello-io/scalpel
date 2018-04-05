use nello::errors::*;

use bytes::Bytes;
use untrusted;

use ring::{rand, signature};
use nello::v2::proto::signature::Signature as InnerSignature;

//#[derive(Debug)]
pub struct Signature {
    inner_signatur: InnerSignature,
    pub keypair: Result<signature::Ed25519KeyPair>,
}


impl Signature {

    pub fn new() -> Self {
        Self{   inner_signatur: InnerSignature::new(),
                keypair: Signature::generate_ed25519_keypair(), }
    }
    // neccessary?
    pub fn len(&self) -> usize {
        self.inner_signatur.len()
    }
    
    // make private and use it directly in sign function?
    /// generate a ed25519 keypair in pkcs8 format
    pub fn generate_ed25519_keypair() -> Result<signature::Ed25519KeyPair> {

        let rng = rand::SystemRandom::new();
        let bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let input = untrusted::Input::from(&bytes);
        let keypair = signature::Ed25519KeyPair::from_pkcs8(input)?;

        Ok(keypair) // error handling?
    }

    /// sign file with generated keypair
    pub fn sign_file(key_pair: signature::Ed25519KeyPair, file: &Bytes) {
        // TODO: proper signing, sign(file) has to return the signature
        let sig = key_pair.sign(&file);
                
    }
    
}