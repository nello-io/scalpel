use std::fs::OpenOptions;
use bytes::{BytesMut};
use std::io::{Read, Write};
use std::path::Path;
use errors::*;

pub fn stitch_files(files: Vec<String>, offsets: Vec<usize>, output: String) -> Result<()> {
    // sort files by offset
    let stitched = files.iter().zip(offsets.iter()).fold(BytesMut::new(), |stitched, (elem, offset)| {
        let content = read_file(elem.to_string())
            .map_err(|e| {
                return ScalpelError::OpeningError.context(e)
            })
            .expect("Failed to open:");
        
        stitch(stitched, content, offset).expect("Failed to stitch")
        
    });


    write_file(Path::new(&output), stitched)?;

    Ok(())
}

fn read_file(name: String) -> Result<BytesMut> {

    let mut file = OpenOptions::new()
        .read(true)
        .open(name)
        .map_err(|err| ScalpelError::OpeningError.context(err))?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(BytesMut::from(buf))
}

fn stitch(mut bytes: BytesMut, new: BytesMut, offset: &usize) -> Result<BytesMut> {
    if bytes.len() < *offset {
        return Err(ScalpelError::OverlapError.into());
    } else {
        bytes.resize(*offset, 0x0);
        bytes.extend_from_slice(&new);
        
        Ok(bytes)
    }
}

fn write_file(path: &Path, bytes: BytesMut) -> Result<()> {
    let path: &Path = path.as_ref();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .map_err(|err| ScalpelError::OpeningError.context(err).context(format!("Failed to open {:?}", path )))?;

    file.write(&bytes)?;

    Ok(())
}
