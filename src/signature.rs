use bytes::Bytes;
use untrusted;

use ring;
use ring::{rand, signature};
use std::path::Path;
use std::io::Read;
use std::fs::OpenOptions;
use errors::*;
use failure::Fail;
use pem::{Pem,parse_many};
use base64;

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
    pub fn calculate_signature<P>(&self,
        path: P,
    ) -> Result<ring::signature::Signature> where P: AsRef<Path> {
        let path : &Path = path.as_ref();

        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .map_err(|err| SigningError::OpeningError.context(err))?;

        let mut content = Vec::<u8>::new();
        file.read_to_end(&mut content)
            .map_err(|err| SigningError::ReadingError.context(err))?;

        let content = Bytes::from(content);
        let signature = self.calculate_signature_from_bytes(&content)?;

        //file.write( signature.as_ref() )?;

        Ok(signature)
    }

    pub fn calculate_signature_from_bytes(&self,
        file: &Bytes,
    ) -> Result<ring::signature::Signature> {
 
        if let Some(ref keypair) = self.keypair {
            Ok(keypair.sign(&file))
        } else {
            // TODO add more error types
            Err(SigningError::ReadingError.context("No key in here yet").into())
        }
    }


    pub fn verify_bytes<B,C>(&self, bytes_data : B, bytes_signature : C)-> Result<()> where B : Into<Bytes>, C: Into<Bytes>{
        if let Some(ref keypair) = self.keypair {

            let bytes_data = bytes_data.into();
            let bytes_signature = bytes_signature.into();

            ring::signature::verify(&ring::signature::ED25519,
            untrusted::Input::from(keypair.public_key_bytes()),
            untrusted::Input::from(&bytes_data),
            untrusted::Input::from(&bytes_signature))?;
            Ok(())
        } else {
            // TODO add more error types
            Err(SigningError::ReadingError.context("No key in here yet").into())
        }

    }

    pub fn verify_file<P>(&self, path : P) -> Result<()> where P: AsRef<Path> {
        let path : &Path = path.as_ref();

        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .map_err(|err| SigningError::OpeningError.context(err))?;

        let mut content = Vec::<u8>::new();
        file.read_to_end(&mut content)
            .map_err(|err| SigningError::ReadingError.context(err))?;
        
        if content.len() > 64 {
            let (data, signature) = content.split_at(content.len()-64);
            self.verify_bytes(data, signature);
            Ok(())
        } else {
            panic!("error me up");
        }
    }

    /// read key from file and return a Signature
    pub fn read_pem(path_file: &Path) -> Result<Signature> {
        // open file
        let mut file = OpenOptions::new()
            .read(true)
            .open(path_file)
            .map_err(|err| SigningError::OpeningError.context(err))?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|err| SigningError::ReadingError.context(err))?;

        let mut pems : Vec<Pem> = parse_many( &content );

        let concatenated = pems.into_iter().fold(Vec::<u8>::new(), |mut acc, mut pem| {
            println!("Key Bytes encoded {}", String::from_utf8_lossy(&pem.contents));
            println!("Key Bytes encoded {:?}", &pem.contents);
            //let mut vec = base64::decode(&pem.contents).expect("Hopefully this is base 64");
            acc.append(&mut pem.contents);
            acc
        });

        // get keypair
        let pkcs8_keys = signature::Ed25519KeyPair::
                from_pkcs8(untrusted::Input::from(concatenated.as_slice()))
                .map_err(|err| SigningError::ParsePemError.context("Failed to create keypair from pkcs8").context(err))?;

        Ok(Signature{ keypair: Some(pkcs8_keys) })
    } 

    /// read key from pkcs8 file (raw bytes, no encoding) and return a Signature
    pub fn read_pk8(path_file: &Path) -> Result<Signature> {
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


#[cfg(test)]
mod test {
    extern crate pem;
    use super::*;
    use pem::*;
    use std::io::Write;

    use ::concat::*;

    #[test]
    fn test_keys() {
        let signer = Signature::read_pem(Path::new("./tmp/test_keypair.pem")).expect("Should work right?");

        let signature = signer.calculate_signature("./tmp/signme.bin").expect("Signing failed");

        append_signature(Path::new("./tmp/signme.bin"), &signature).expect("Failed to append signature");
        
        // 
        assert!(signer.verify_file(Path::new("./tmp/signme-signed.bin")).is_ok());

    }

    #[test]
    fn test_keys2() {
        let sig = Signature::new();
        let pem_public = Pem {
            tag: String::from("Public Key"),
            contents: Vec::from(sig.keypair.unwrap().public_key_bytes()),
        };

        let pem_string = encode(&pem_public);
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open("tmp/publicKey_test.pem")
            .expect("Failed to create public key file");

        file.write( pem_string.as_bytes() ).expect("Failed to write publix key to file");
        
    }
}