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
    let mut f_in = open_file(victim, READ)?;
    let mut f_out = open_file(output, WRITE)?;

    f_in.seek(SeekFrom::Start(start))
        .map_err(|err| SigningError::SeekError.context(err))?;

    let mut remaining = size;
    loop {
        let mut fragment = vec![0; fragment_size];
        f_in.read(&mut fragment[..])
            .map_err(|err| SigningError::ReadingError.context(err))?;

        if remaining < fragment_size as u64 {
            f_out
                .write_all(&fragment[0..(remaining as usize)])
                .map_err(|err| SigningError::WritingError.context(err))?;

            return Ok(());
        } else {
            f_out
                .write_all(&fragment[..])
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
            .create(true)
            .open(file.as_str())
            .map_err(|err| SigningError::OpeningError.context(err))?;

        Ok(f_out)
    }
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;
    use self::rand::Rng;
    use std::iter;

    #[test]
    fn test_open_files() {
        // generate test file with random content, read it once manually and once
        // with the tested function, compare the content
        
        // random content generation
        let mut rng = rand::thread_rng();
        let testvec: Vec<u8> = iter::repeat(1)
            .take(1000)
            .map(|_| rng.gen_range(1, 15))
            .collect::<Vec<u8>>();
        // write file with this content
        let victim = String::from("tmp/test_bytes");
        {
            let mut file_tester = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(victim.clone())
                .expect("Failed to open file");
            file_tester
                .write_all(&testvec)
                .expect("Failed to write to file");
        }
        // read the generated file
        let mut file_tested = open_file(victim.clone(), true).expect("Failed to open tested File");
        let mut file_tester = OpenOptions::new()
            .read(true)
            .open(victim)
            .expect("Failed to open file");
        let mut content_tested = Vec::new();
        let mut content_tester = Vec::new();
        file_tested
            .read(&mut content_tested)
            .expect("Failed to read tested File");
        file_tester
            .read(&mut content_tester)
            .expect("Failed to read Tester-File");
        // compare read content
        assert_eq!(content_tested, content_tester);
    }

    #[test]
    fn test_cut_out() {
        // generate file with known byte content and cut some bytes out,
        // compare resulting file with bytes
        let bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16];
        // write file with this content
        let victim = String::from("tmp/test_cut");
        {
            let mut file_tester = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(victim.clone())
                .expect("Failed to open file");
            file_tester
                .write_all(&bytes)
                .expect("Failed to write to file");
        }
        // cut bytes from this file
        let output = String::from("tmp/test_cut_out");
        cut_out_bytes(victim, output.clone(), 5, 4, 1).expect("Failed to cut");

        // read content of output
        let mut output_bytes = vec![0,0,0,0];
        let mut file_tested = OpenOptions::new()
            .read(true)
            .open(output)
            .expect("Failed to open ouput file");
        file_tested
            .read( &mut output_bytes)
            .expect("Failed to read file");

        println!("{:?}", output_bytes );
        assert_eq!( output_bytes, &bytes[5..9]);
    }

}
