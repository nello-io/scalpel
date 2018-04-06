use ring::signature;
use std::fs::OpenOptions;
use std::io::{Write,Read};
use bytes::Bytes;

/// takes a file and cretes a copy with signature appended
pub fn append_signature( file: String, sig: &signature::Signature) -> Result<i32, i32> {
    // open output file, add "-signed" to name
    let file_sig = format!("{}-signed", file);
    let mut f_out = match OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open( file_sig.as_str() ) {
                                        Ok(file) => file,
                                        Err(e)  => {
                                            error!("Failed to open {}: {}", file, e);
                                            return Err(37);
                                        },
                                    };
    // open input file
    let mut f_in = match OpenOptions::new()
                                    .read(true)
                                    .open( file.as_str()) {
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
    
    Ok(0) //TODO: return 0 when succeeded?
}