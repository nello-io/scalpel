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
  scalpel sign <victimfile>
  scalpel (-h | --help)
  scalpel (-v |--version)

Commands:
  cut   extract bytes from a binary file
  sign  sign binary with ED25519 Key Pair

Options:
  -h --help     Show this screen.
  -v --version     Show version.
  --start=<start>  Start byte offset of the section to cut out. If omitted, set to 0.
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

        let signed = Signature::sign_file(sig.keypair.unwrap(), &test_bytes);

        std::process::exit(0);
    } else if args.cmd_cut {    // command cut

        // do input handling
        let start = args.flag_start.unwrap_or(0) as u64; // if none, set to 0
        let size : u64 =
            if let Some(end) = args.flag_end {
                if let Some(_) = args.flag_size {
                    error!("Either end or size has to be specified, not both");
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
                //TODO: error message reasonable?
                error!("end addr should be larger than start addr");
                std::process::exit(36);
            };
        let fragment_size = args.flag_fragment.unwrap_or(8192) as usize; // CHUNK from cut

        match cut::cut_out_bytes( start,
                            size,
                            args.arg_victimfile,
                            args.flag_output,
                            fragment_size) {
                                Ok(_) => info!("Cutting succeeded."),
                                Err(e) => std::process::exit(e),
                            }
    }

    info!("scalpel operation complete");

    std::process::exit(0);
}


