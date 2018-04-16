use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

use errors::*;
//use failure::Fail;

pub fn cut_out_bytes(
    start: u64,
    size: u64,
    victim: String,
    output: String,
    fragment_size: usize,
) -> Result<()> {

    let mut f_out = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create_new(true)
        .open(output.as_str())
        .map_err(|err| SigningError::OpeningError.context(err))?;

    let mut f_in = OpenOptions::new()
        .read(true)
        .open(victim.as_str())
        .map_err(|err| SigningError::OpeningError.context(err))?;

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

/*#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cut_out_bytes() {
        let victim = String::from("tmp/test_bytes");
        let output = String::from("tmp/test_bytes_cut");
        cut_out_bytes(0, 10, victim, output, 8192).expect("Cut of bytes failed.");
    }

}*/
