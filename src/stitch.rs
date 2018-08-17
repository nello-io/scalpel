use std::fs::OpenOptions;
use bytes::{BytesMut};
use std::io::{Read, Write};
use std::path::Path;
use errors::*;

#[derive(Deserialize, Debug)]
pub enum FillPattern { Random, Zero, One}

impl Default for FillPattern {
    fn default() -> Self {
        FillPattern::Zero
    }
}

pub fn stitch_files(files: Vec<String>, offsets: Vec<usize>, output: String, fill_pattern: FillPattern) -> Result<()> {
    
    // TODO: sort files by offset
    let (files, offsets) = sort_vec_by_offset(files, offsets)?;

    let stitched: Result<BytesMut>
     = files.iter().zip(offsets.iter()).try_fold(BytesMut::new(), |stitched, (elem, offset)| {
        let content = read_file(elem.to_string())
            .map_err(|e| {
                return ScalpelError::OpeningError.context(e)
            })?;
        
        Ok(stitch(stitched, content, offset, &fill_pattern)?)
        
    });

    write_file(Path::new(&output), stitched?)?;

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

fn stitch(mut bytes: BytesMut, new: BytesMut, offset: &usize, fill_pattern: &FillPattern) -> Result<BytesMut> {
    if bytes.len() > *offset {
        return Err(ScalpelError::OverlapError.into());
    } else {
        match fill_pattern {
            FillPattern::Zero => bytes.resize(*offset, 0x0),
            FillPattern::One => bytes.resize(*offset, 0x1),
            FillPattern::Random => unimplemented!(),
        }
        bytes.extend_from_slice(&new);
        debug!("Length: {}", &bytes.len());
        Ok(bytes)
    }
}

fn write_file(path: &Path, bytes: BytesMut) -> Result<()> {
    
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .map_err(|err| ScalpelError::OpeningError.context(err).context(format!("Failed to open {:?}", path )))?;

    file.write(&bytes)?;

    Ok(())
}

pub fn sort_vec_by_offset<T>(vec: Vec<T>, offset: Vec<usize>) -> Result<(Vec<T>, Vec<usize>)>
where T: Clone,
{

    let mut offset_sorted = offset.clone();
    offset_sorted.sort_unstable();

    let sorted_vec =  offset_sorted.iter().map(|elem|  {
        println!("looking for {} in {:?}",&elem, &offset );
        let ind_o: usize = offset.iter().position(|&s| &s == elem).expect("Failed to sort");
        vec[ind_o].clone()
    }).collect();

    Ok((sorted_vec, offset_sorted))
}