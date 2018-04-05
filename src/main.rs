#[macro_use]
extern crate log;
extern crate env_logger;
extern crate nello;
extern crate untrusted;
#[macro_use]
extern crate serde_derive;
extern crate docopt;
extern crate bytes;
extern crate ring;
extern crate failure;


use docopt::Docopt;
use bytes::Bytes;

mod signature;
use signature::*;

mod cut;

const USAGE: &'static str = "
scalpel

Usage:
  scalpel cut [--fragment=<fragment>] [--start=<start>] --end=<end> --output=<output> <victimfile>
  scalpel cut [--fragment=<fragment>] [--start=<start>] --size=<size> --output=<output> <victimfile>
  scalpel sign <victimefile>
  scalpel (-h | --help)
  scalpel (-v |--version)

Commands:
  cut   extract bytes from a binary file
  sign  sign binary with ED25519 Key Pair

Options:
  -h --help     Show this screen.
  -v --version     Show version.
  --start=<start>  Start byte offset of the section to cut out.
  --end=<end>      The end byte offset which will not be included.
  --size=<size>    Alternate way to sepcify the <end> combined with start.
  --fragment=<fragment>  Define the size of the fragment/chunk to read/write at once.
  --sign    sign and verify a binary
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
        println!("{} {}",NAME , VERSION);
        std::process::exit(0);
    } else if args.flag_help {
        println!("{}", USAGE);
        std::process::exit(0);
    } else if args.cmd_sign {   // command sign
        println!("Signing file...");
        // TODO: sign file properly
        let test_bytes = Bytes::from(&b"This is a text message"[..]);

        let mut sig = Signature::new();
        sig.keypair = Signature::generate_ed25519_keypair();

        Signature::sign_file(sig.keypair.unwrap(), &test_bytes);
        
        std::process::exit(0);
    } else if args.cmd_cut {    // command cut
        cut::cut_out_bytes( args.flag_start,
                            args.flag_end,
                            args.flag_size, 
                            args.arg_victimfile,
                            args.flag_output);
    }

    info!("scalpel operation complete");

    std::process::exit(0);
}


