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
        .create_new(true)
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

/*#[cfg(test)]
mod test {
    use super::*;
    
    /*#[test]
    fn test_append_signature() {
        let path_victim = Path::new("tmp/test_bytes");
        append_signature( &path_victim , &signature).expect("Appending signature failed.");

    }*/

    #[test]
    fn test_read_to_bytes(){
        let path_victim = Path::new("tmp/test_bytes");
        read_to_bytes(path_victim).expect("Reading to bytes failed.");
    }
}
*/