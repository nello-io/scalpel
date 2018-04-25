use bytes::Bytes;
use untrusted;

use ring;
use ring::{rand, signature};
use std::path::Path;
use std::io::Read;
use std::fs::OpenOptions;
use errors::*;

pub struct Signature {
    pub keypair: Option<signature::Ed25519KeyPair>,
}

impl Signature {
    pub fn new() -> Self {
        Self {
            keypair: Signature::generate_ed25519_keypair(),
        }
    }

    /// generate a ed25519 keypair in pkcs8 format
    fn generate_ed25519_keypair() -> Option<signature::Ed25519KeyPair> {
        let rng = rand::SystemRandom::new();
        let bytes = match signature::Ed25519KeyPair::generate_pkcs8(&rng) {
            Ok(byt) => byt,
            Err(_) => return None,
        };
        let input = untrusted::Input::from(&bytes);
        match signature::Ed25519KeyPair::from_pkcs8(input) {
            Ok(key) => Some(key),
            Err(_) => None,
        }
    }

    /// sign file with generated keypair
    pub fn sign_file(
        key_pair: signature::Ed25519KeyPair,
        file: &Bytes,
    ) -> ring::signature::Signature {
        key_pair.sign(&file)
    }

    /// read key from file and return a Signature
    pub fn read_key(path_file: &Path) -> Result<Signature> {
        // open file
        let mut file = OpenOptions::new()
            .read(true)
            .open(path_file)
            .map_err(|err| SigningError::OpeningError.context(err))?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|err| SigningError::ReadingError.context(err))?;

        // get keypair
        let pkcs8_keys = signature::Ed25519KeyPair::
                from_pkcs8(untrusted::Input::from(&content))
                .map_err(|err| SigningError::ParsePemError.context(err))?;
        // return
        Ok(Signature{ keypair: Some(pkcs8_keys) })
    }
}