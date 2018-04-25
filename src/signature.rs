use bytes::Bytes;
use untrusted;

use ring;
use ring::{rand, signature};
use std::path::Path;
use std::io::Read;
use std::fs::OpenOptions;
use errors::*;
use failure::Fail;
use pem::{parse_many, Pem};

pub struct Signer {
    pub keypair: Option<signature::Ed25519KeyPair>,
}

impl Signer {
    pub fn new() -> Self {
        Self {
            keypair: Signer::generate_ed25519_keypair(),
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

    /// get signature of file
    pub fn calculate_signature<P>(&self, path: P) -> Result<ring::signature::Signature>
    where
        P: AsRef<Path>,
    {
        let path: &Path = path.as_ref();

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

        Ok(signature)
    }

    /// get signature for bytes
    pub fn calculate_signature_from_bytes(
        &self,
        file: &Bytes,
    ) -> Result<ring::signature::Signature> {
        if let Some(ref keypair) = self.keypair {
            Ok(keypair.sign(&file))
        } else {
            Err(SigningError::KeyInitError
                .context("No key in here yet")
                .into())
        }
    }

    /// verify bytes with provided signature bytes
    pub fn verify_bytes<B, C>(&self, bytes_data: B, bytes_signature: C) -> Result<()>
    where
        B: Into<Bytes>,
        C: Into<Bytes>,
    {
        if let Some(ref keypair) = self.keypair {
            let bytes_data = bytes_data.into();
            let bytes_signature = bytes_signature.into();

            ring::signature::verify(
                &ring::signature::ED25519,
                untrusted::Input::from(keypair.public_key_bytes()),
                untrusted::Input::from(&bytes_data),
                untrusted::Input::from(&bytes_signature),
            )?;
            Ok(())
        } else {
            Err(SigningError::KeyInitError
                .context("No key in here yet")
                .into())
        }
    }

    /// verify signature in file with actual signature
    pub fn verify_file<P>(&self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let path: &Path = path.as_ref();

        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .map_err(|err| SigningError::OpeningError.context(err))?;

        let mut content = Vec::<u8>::new();
        file.read_to_end(&mut content)
            .map_err(|err| SigningError::ReadingError.context(err))?;

        if content.len() > 64 {
            let (data, signature) = content.split_at(content.len() - 64);
            self.verify_bytes(data, signature)?;
            Ok(())
        } else {
            Err(SigningError::ContentError
                .context("File to short, no signature included")
                .into())
        }
    }

    /// read key from pkcs8 file (raw bytes, no encoding) and return a Signature
    pub fn read_pk8(path_file: &Path) -> Result<Signer> {
        // open file
        let mut file = OpenOptions::new()
            .read(true)
            .open(path_file)
            .map_err(|err| SigningError::OpeningError.context(err))?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|err| SigningError::ReadingError.context(err))?;

        // get keypair
        let pkcs8_keys = signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&content))
            .map_err(|err| SigningError::ParsePk8Error.context(err))?;
        // return
        Ok(Signer {
            keypair: Some(pkcs8_keys),
        })
    }
}

#[cfg(test)]
mod test {
    extern crate pem;
    use super::*;

    use concat::*;

    #[test]
    fn test_keys_pk8() {
        let signer =
            Signer::read_pk8(Path::new("./tmp/ed25519_keypair.pk8")).expect("Should work right?"); //./tmp/ed25519_private-2.pk8

        let signature = signer
            .calculate_signature("./tmp/signme.bin")
            .expect("Signing failed");

        append_signature(Path::new("./tmp/signme.bin"), &signature)
            .expect("Failed to append signature");

        assert!(
            signer
                .verify_file(Path::new("./tmp/signme-signed.bin"))
                .is_ok()
        );
    }
}
