use ring::signature;
use std::fs::OpenOptions;
use std::io::{Write,Read};
use std::path::Path;
use bytes::Bytes;

/// takes a file and cretes a copy with signature appended
pub fn append_signature( path: &Path, sig: &signature::Signature) -> Result<(), i32> {
    // get file
    let file_result = path.to_str();
    let file = match file_result {
        Some(file) => file,
        None  => {
            error!("Failed to resolve path {:?}", &path);
            return Err(37);
        },
    };

    // open output file, add "-signed" to name
    let file_split: Vec<&str> = file.rsplitn(2, '.').collect();
    let file_sig;
    if file_split.len() > 1 {
        file_sig = format!("{}-signed.{}", file_split[1], file_split[0]);
    } else {
        file_sig = format!("{}-signed", file_split[0]);
    }
    let mut f_out = match OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open( file_sig.as_str() ) {
                                        Ok(file) => file,
                                        Err(e)  => {
                                            error!("Failed to create {}: {}", file, e);
                                            return Err(37);
                                        },
                                    };
    // open input file
    let mut f_in = match OpenOptions::new()
                                    .read(true)
                                    .open( path ) {
                                        Ok(file) => file,
                                        Err(e)  => {
                                            error!("Failed to open {}: {}", file, e);
                                            return Err(34);
                                        },
                                    };
    // read input file to buffer
    let mut content: Vec<u8> = Vec::new();
    if let Err(e) = f_in.read_to_end( &mut content){
        error!("Failed to read {}: {:?}", &file, e);
        return Err(38);
    }

    // write input to new file, afterwards append signature
    if let Err(e) = f_out.write_all( &content){
        error!("Failed to write file content: {:?}", e);
        return Err(7);
    };
    let byte_sig = Bytes::from(sig.as_ref());
    if let Err(e) = f_out.write_all( &byte_sig ){
        error!("Failed to write signature: {:?}", e);
        return Err(7);
    }
    
    Ok(())
}

pub fn read_to_bytes( path: &Path ) -> Result<Bytes, i32> {
    // open file
        let mut victim = match OpenOptions::new().read(true).open( path ) {
            Ok(file) => file,
            Err(e)  => {
                error!("Failed to open {:?}: {:?}", &path, e);
                return Err(34);
            }
        };
        // read file to Bytes
        let mut content: Vec<u8> = Vec::new();
        if let Err(e) = victim.read_to_end( &mut content){
            error!("Failed to read {:?}: {:?}", &path, e);
            return Err(38);
        }
        // convert buf to Bytes
        Ok(Bytes::from(content))
}

/*#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn fx() {
        Ok().expect("Sign failed");
    }
}
*/