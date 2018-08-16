use std::fs::OpenOptions;
use bytes::{BufMut, BytesMut};
use std::io::{Read, Write};
use std::path::Path;
use errors::*;

pub fn stitch_files(files: Vec<String>, offsets: Vec<u64>, output: String) -> Result<()> {

    let stitched = files.iter().fold(BytesMut::new(), |stitched, elem| {//.zip(offsets.iter()).fold(BytesMut::new(), |stitched, (elem, offset)| {
        let content = read_file(elem.to_string()).expect("Failed to read");
        let stitched = stitch(stitched, content).expect("Failed to stitch");
        
        stitched
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

fn stitch(bytes: BytesMut, new: BytesMut) -> Result<BytesMut> {
    println!("Length: {}, {}", bytes.len(), new.len());
    let length = bytes.len() + new.len();
    let mut buf = BytesMut::with_capacity(length).writer();

    buf.write(&new)?;

    Ok(buf.into_inner())

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
