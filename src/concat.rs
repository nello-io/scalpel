use ring::signature;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use bytes::Bytes;

use errors::*;

/// takes a file and creates a copy with signature appended
pub fn append_signature(path: &Path, sig: &signature::Signature) -> Result<()> {
    // get file
    let file = path.to_str()
        .ok_or::<Error>(SigningError::OpeningError.into())?;

    // open output file, add "-signed" to name
    let file_split: Vec<&str> = file.rsplitn(2, '.').collect();
    let file_sig;
    if file_split.len() > 1 {
        file_sig = format!("{}-signed.{}", file_split[1], file_split[0]);
    } else {
        file_sig = format!("{}-signed", file_split[0]);
    }

    // create output file
    let mut f_out = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(Path::new(&file_sig))
        .map_err(|err| SigningError::OpeningError.context(err))?;

    // open input file
    let mut f_in = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|err| SigningError::OpeningError.context(err))?;

    // read input file to buffer
    let mut content: Vec<u8> = Vec::new();
    f_in.read_to_end(&mut content)
        .map_err(|err| SigningError::OpeningError.context(err))?;

    // write input to new file, afterwards append signature
    f_out
        .write_all(&content)
        .map_err(|err| SigningError::OpeningError.context(err))?;

    let byte_sig = Bytes::from(sig.as_ref());

    f_out
        .write_all(&byte_sig)
        .map_err(|err| SigningError::OpeningError.context(err))?;

    Ok(())
}

pub fn read_to_bytes(path: &Path) -> Result<Bytes> {
    // open file
    let mut victim = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|err| SigningError::ReadingError.context(err))?;

    // read file to Bytes
    let mut content: Vec<u8> = Vec::new();
    victim
        .read_to_end(&mut content)
        .map_err(|err| SigningError::ReadingError.context(err))?;
    // convert buf to Bytes
    Ok(Bytes::from(content))
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;
    use self::rand::Rng;
    use std::iter;
    use signature::*;
    use std::io::{Seek, SeekFrom};
    
    #[test]
    fn test_append_signature() {
        let sig = Signature::new();
        
        //random content generation
        let mut rng = rand::thread_rng();
        let byte_victim = iter::repeat(1)
            .take(1000)
            .map(|_| rng.gen_range(1, 255))
            .collect::<Bytes>();
        let signature = Signature::sign_file(sig.keypair.unwrap(), &byte_victim );
        let path_victim = Path::new("tmp/test_bytes");
        append_signature( &path_victim , &signature).expect("Appending signature failed.");
        
        // open signed file and compare signature, path is hardcoded
        let path_victim = Path::new("tmp/test_bytes-signed");
        let mut f_in = OpenOptions::new()
            .read(true)
            .open(&path_victim)
            .expect("Failed to read signed File");
        // read from end of file for the length of singature
        let ref_sig = signature.as_ref();
        let mut read_sig = vec![0 ; ref_sig.len() ]; 

        f_in.seek(SeekFrom::End( -(ref_sig.len() as i64) )).expect("Failed to seek from end");
        f_in.read( &mut read_sig ).expect("Failed to Read Signature");
        println!("{}", read_sig.len());
        
        assert_eq!(ref_sig[..], read_sig[..] );

    }

    #[test]
    fn test_read_to_bytes(){
        // random content generation
        let mut rng = rand::thread_rng();
        let ref_bytes = iter::repeat(1)
            .take(1000)
            .map(|_| rng.gen_range(1, 255))
            .collect::<Bytes>();
        let path = Path::new("tmp/test_bytes");
        {
            // write content to file
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open( &path )
                .expect("Failed to open file");
            file.write( &ref_bytes).expect("Failed to write bytes");
        }
        
        // read file and compare
        let read_bytes = read_to_bytes(path).expect("Reading to bytes failed.");
        assert_eq!(read_bytes, ref_bytes);
    }
}
