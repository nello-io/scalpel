#[macro_use] extern crate log;
extern crate env_logger;


#[macro_use]
extern crate serde_derive;
extern crate docopt;

use docopt::Docopt;



use std::fs::*;


use std::io::{Write,Read,Seek,SeekFrom};


const USAGE: &'static str = "
scalpel

Usage:
  scalpel [--fragment=<fragment>] [--start=<start>] --end=<end> --output=<output> <victimfile>
  scalpel [--fragment=<fragment>] [--start=<start>] --size=<size> --output=<output> <victimfile>
  scalpel (-h | --help)
  scalpel (-v |--version)

Options:
  -h --help     Show this screen.
  --version     Show version.
  --start=<start>  Start byte offset of the section to cut out.
  --end=<end>      The end byte offset which will not be included.
  --size=<size>    Alternate way to sepcify the <end> combined with start.
  --fragment=<fragment>  Define the size of the fragment/chunk to read/write at once.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_start: Option<u64>,
    flag_end: Option<u64>,
    flag_size: Option<u64>,
    flag_fragment: Option<usize>,
    flag_output: String,
    arg_victimfile: String,
}

fn main() {
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.deserialize())
                            .unwrap_or_else(|e| e.exit());

    let start = args.flag_start.unwrap_or(0) as u64;
    let size : u64 =
        if let Some(end) = args.flag_end {
            if let Some(_) = args.flag_size {
                error!("Either end of size has to be specified, not both");
                std::process::exit(31);
            }
            if start >= end {
                error!("end addr {1} should be larger than start addr {0}", start, end);
                std::process::exit(34);
            }
            end - start
        } else if let Some(size) = args.flag_size {
            size
        } else {
            error!("end addr should be larger than start addr");
            std::process::exit(36);
        };

    let victim = args.arg_victimfile;
    let output = args.flag_output;


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

    const CHUNK : usize = 8192; // args.flag_fragment_size;

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

    info!("scalpel operation complete");

    std::process::exit(0);
}
