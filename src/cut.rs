use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use errors::*;
//use failure::Fail;

pub fn cut_out_bytes(
    victim: String,
    output: String,
    start: u64,
    size: u64,
    fragment_size: usize,
) -> Result<()> {

    const READ: bool = true;
    const WRITE: bool = false;

    let mut f_out = open_file(output, READ )?;

    let mut f_in = open_file(victim, WRITE)?;

    f_in.seek(SeekFrom::Start(start))
        .map_err(|err| SigningError::SeekError.context(err))?;

    let mut remaining = size;
    loop {
        let mut fragment = vec![0; fragment_size];
        f_in.read(&mut fragment[..])
            .map_err(|err| SigningError::ReadingError.context(err) )?;

        if remaining < fragment_size as u64 {
            f_out.write_all(&fragment[0..(remaining as usize)])
                .map_err(|err| SigningError::WritingError.context(err))?;
            
            return Ok(());
        } else {
            f_out.write_all(&fragment[..])
                .map_err(|err| SigningError::WritingError.context(err))?;
            remaining -= fragment_size as u64;
        }
    }
}

/// File Open utility for cutting bytes
fn open_file(file: String, rw: bool) -> Result<File> {
    
    if rw {
        let f_in = OpenOptions::new()
        .read(true)
        .open(file.as_str())
        .map_err(|err| SigningError::OpeningError.context(err))?;

        Ok(f_in)
    } else {
        let f_out = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create_new(true)
            .open(file.as_str())
            .map_err(|err| SigningError::OpeningError.context(err))?;

            Ok(f_out)
    }

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cut_out_bytes() {
        let testvec = vec![0u8, 10u8, ...]; // Iter::repeat().take(1000).collect::<Vec<u8>>();
        let victim = String::from("tmp/test_bytes");
        {
            let testfile = OpenOptions::new().write(true).open(victim).expect("Failed to open file");
            testfile.write()
        }
        let output = String::from("tmp/test_bytes_cut");
        assert!(cut_out_bytes(0, 10, victim, output, 8192).is_ok());
    }

    #[test]
    fn test_bufferd_cut_out() {
        let bytes : &[u8] = &[0,1,2,3,4,5,6,7,8,10,11,12,13];


        let output_bytes = cut_out_bytes(2,3, vicitim_bytes).expect("Failed to cut");

        assert_eq!(output_bytes, &bytes[2..5]);
    }

}
