use std;
use std::fs::*;
use std::io::{Write,Read,Seek,SeekFrom};

// TODO: pull parameter handling back to main method, only pass values, no options
pub fn cut_out_bytes(start: u64,
                        size: u64,
                        victim: String,
                        output: String) -> Result<i32, i32> {
   
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

    const CHUNK : usize = 8192; // TODO: args.flag_fragment_size;

    let mut remaining = size;
    loop {
        let mut fragment : [u8;CHUNK] = [0;CHUNK];
        if let Err(_) = f_in.read(&mut fragment[..]) {
            error!("Failed to read in fragment");
            return Err(38);
        }
        if remaining < CHUNK as u64 {
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
            remaining -= CHUNK as u64;
        }
    }


}