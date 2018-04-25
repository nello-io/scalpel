#[macro_use]
extern crate log;
extern crate env_logger;
extern crate untrusted;
#[macro_use]
extern crate serde_derive;
extern crate bytes;
extern crate docopt;
extern crate ring;
extern crate serde;

extern crate base64;
extern crate pem;

#[macro_use]
extern crate failure;

use docopt::Docopt;
use std::path::Path;

mod signature;
use signature::*;

mod cut;
mod concat;
mod errors;

const USAGE: &'static str = "
scalpel

Usage:
  scalpel cut [--fragment=<fragment>] [--start=<start>] --end=<end> --output=<output> <victimfile>
  scalpel cut [--fragment=<fragment>] [--start=<start>] --size=<size> --output=<output> <victimfile>
  scalpel sign <victimfile> <keyfile> --format=<informat>
  scalpel (-h | --help)
  scalpel (-v |--version)

Commands:
  cut   extract bytes from a binary file
  sign  sign binary with ED25519 Key Pair, key has to be a .pem file

Options:
  -h --help     Show this screen.
  -v --version     Show version.
  --start=<start>  Start byte offset of the section to cut out. If omitted, set to 0.
  --end=<end>      The end byte offset which will not be included.
  --size=<size>    Alternate way to sepcify the <end> combined with start.
  --fragment=<fragment>  Define the size of the fragment/chunk to read/write at once.
  --format=<informat>   specify the key format, eihter pkcs8, pem or bytes
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_cut: bool,
    cmd_sign: bool,
    flag_start: Option<u64>,
    flag_end: Option<u64>,
    flag_size: Option<u64>,
    flag_fragment: Option<usize>,
    flag_output: String,
    arg_victimfile: String,
    arg_keyfile: String,
    flag_format: String,
    flag_version: bool,
    flag_help: bool,
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const NAME: &'static str = env!("CARGO_PKG_NAME");

fn main() {
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // check arguments
    if args.flag_version {
        println!("{} {}", NAME, VERSION);
        std::process::exit(0);
    } else if args.flag_help {
        println!("{}", USAGE);
        std::process::exit(0);
    } else if args.cmd_sign {
        // command sign

        let path_victim = Path::new(&args.arg_victimfile);
        let byte_victim = match concat::read_to_bytes(path_victim) {
            Ok(bytes) => bytes,
            Err(_) => std::process::exit(77), // TODO stop codes
        };

        let keys = if args.flag_format == String::from("pkcs8") {
            let key_path = Path::new(&args.arg_keyfile);
            match Signer::read_pk8(&key_path) {
                Ok(key) => key,
                Err(e) => {
                    error!("{}", e);
                    std::process::exit(77);
                }
            }
        } else if args.flag_format == String::from("pem") {
            unimplemented!();
        } else if args.flag_format == String::from("bytes") {
            unimplemented!();
        } else {
            println!("File format for key not recognized, use one of the specified formats");
            std::process::exit(1);
        };
        let signature = keys.calculate_signature_from_bytes(&byte_victim)
            .expect("We should have read a key earlier");

        // create signed file
        if let Err(e) = concat::append_signature(&path_victim, &signature) {
            error!("Failed to sign {:?}", e);
            std::process::exit(77);
        }

        // test the verification
        let signed_filename = concat::derive_output_filename(path_victim)
            .unwrap_or_else(|err| {
                error!("Failed to derive file name of signed file: {:?}", err);
                std::process::exit(77);}
            );
        keys.verify_file(Path::new(&signed_filename))
            .unwrap_or_else(|err| {
                error!("Failed to verify: {:?}", err);
                std::process::exit(77);}
            );

        info!("singing succeeded.");
        std::process::exit(0);
    } else if args.cmd_cut {
        // command cut

        // do input handling
        let start = args.flag_start.unwrap_or(0) as u64; // if none, set to 0
        let size: u64 = if let Some(end) = args.flag_end {
            if let Some(_) = args.flag_size {
                error!("Either end or size has to be specified, not both");
                std::process::exit(31);
            }
            if start >= end {
                error!(
                    "end addr {1} should be larger than start addr {0}",
                    start, end
                );
                std::process::exit(34);
            }
            end - start
        } else if let Some(size) = args.flag_size {
            size
        } else {
            //TODO: error message reasonable?
            error!("end addr should be larger than start addr");
            std::process::exit(36);
        };
        let fragment_size = args.flag_fragment.unwrap_or(8192) as usize; // CHUNK from cut

        match cut::cut_out_bytes(
            args.arg_victimfile,
            args.flag_output,
            start,
            size,
            fragment_size,
        ) {
            Ok(_) => info!("Cutting succeeded."),
            Err(_) => std::process::exit(77),
        }
    }

    info!("scalpel operation complete");

    std::process::exit(0);
}
