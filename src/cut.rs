use std;
use std::fs::*;
use std::io::{Write,Read,Seek,SeekFrom};


pub fn cut_out_bytes(   flag_start: Option<u64>,
                    flag_end: Option<u64>,
                    flag_size: Option<u64>,
                    arg_victimfile: String,
                    flag_output: String) {

    let start = flag_start.unwrap_or(0) as u64;
    let size : u64 =
        if let Some(end) = flag_end {
            if let Some(_) = flag_size {
                error!("Either end or size has to be specified, not both");
                std::process::exit(31);
            }
            if start >= end {
                error!("end addr {1} should be larger than start addr {0}", start, end);
                std::process::exit(34);
            }
            end - start
        } else if let Some(size) = flag_size {
            size
        } else {
            error!("end addr should be larger than start addr");
            std::process::exit(36);
        };

    let victim = arg_victimfile;
    let output = flag_output;


    let mut f_out = OpenOptions::new()
                                    .write(true)
                                    .truncate(true)
                                    .create_new(true)
                                    .open(output.as_str())
                                    .unwrap_or_else(
                                        |e| {
                                            error!("Failed to open \"{}\" {:?}", output, e);
                                            std::process::exit(37);
                                        } );

    let mut f_in = OpenOptions::new().read(true)
        .open(victim.as_str()).unwrap_or_else(|e| {
        error!("Failed to open \"{}\" {:?}", victim, e);
        std::process::exit(34);
    } );
    if let Err(_) = f_in.seek(SeekFrom::Start(start)) {
        error!("Failed to seek to start");
        std::process::exit(39);
    }

    const CHUNK : usize = 8192; // TODO args.flag_fragment_size;

    let mut remaining = size;
    loop {
        let mut fragment : [u8;CHUNK] = [0;CHUNK];
        if let Err(_) = f_in.read(&mut fragment[..]) {
            error!("Failed to read in fragment");
            std::process::exit(38);
        }
        if remaining < CHUNK as u64 {
            if let Err(_) = f_out.write_all(&fragment[0..(remaining as usize)]) {
                error!("Failed to write out fragment");
                std::process::exit(7);
            }
            break;
        } else {
            if let Err(_) = f_out.write_all(&fragment[..]) {
                error!("Failed to write out last fragment");
                std::process::exit(7);
            }
            remaining -= CHUNK as u64;
        }
    }


}