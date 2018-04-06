use std::fs::OpenOptions;
use std::io::{Write,Read,Seek,SeekFrom};

pub fn cut_out_bytes(start: u64,
                        size: u64,
                        victim: String,
                        output: String,
                        fragment_size: usize) -> Result<i32, i32> {
   
    let mut f_out = match OpenOptions::new()
                                    .write(true)
                                    .truncate(true)
                                    .create_new(true)
                                    .open(output.as_str()) {
                                        Ok(fil) => fil,
                                        Err(e)  => { error!("Failed to open \"{}\" {:?}", output, e);
                                            return Err(37);
                                        },
                                    };

    let mut f_in = match OpenOptions::new()
                            .read(true)
                            .open(victim.as_str()) {
                                Ok(fil) => fil,
                                Err(e)  => {
                                    error!("Failed to open \"{}\" {:?}", victim, e);
                                    return Err(34);
                                },
                            };

    if let Err(_) = f_in.seek(SeekFrom::Start(start)) {
        error!("Failed to seek to start");
        return Err(39);
    }

    let mut remaining = size;
    loop {
        let mut fragment = vec!(0; fragment_size);
        if let Err(_) = f_in.read(&mut fragment[..]) {
            error!("Failed to read in fragment");
            return Err(38);
        }
        if remaining < fragment_size as u64 {
            if let Err(_) = f_out.write_all(&fragment[0..(remaining as usize)]) {
                error!("Failed to write out fragment");
                return Err(7);
            }
            return Ok(0);
        } else {
            if let Err(_) = f_out.write_all(&fragment[..]) {
                error!("Failed to write out last fragment");
                return Err(7);
            }
            remaining -= fragment_size as u64;
        }
    }


}