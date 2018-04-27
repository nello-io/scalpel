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
#[macro_use]
extern crate common_failures;
#[macro_use]
extern crate failure;

use docopt::Docopt;
use std::path::Path;

mod signature;
use signature::*;

mod cut;
mod concat;
mod errors;
use errors::*;

const USAGE: &'static str = "
scalpel

Usage:
  scalpel cut [--fragment=<fragment>] [--start=<start>] --end=<end> --output=<output> <victimfile>
  scalpel cut [--fragment=<fragment>] [--start=<start>] --size=<size> --output=<output> <victimfile>
  scalpel sign <victimfile> <keyfile> --format=<format>
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
  --format=<format>   specify the key format, eihter pkcs8, pem, bytes or new
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


quick_main!(run);

fn run() -> Result<()> {
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // check arguments
    if args.flag_version {
        println!("{} {}", NAME, VERSION);
        return Ok(())
    } else if args.flag_help {
        println!("{}", USAGE);
        return Ok(())
    } else if args.cmd_sign {
        // command sign

        let path_victim = Path::new(&args.arg_victimfile);
        // get keys from the specified input file
        let keys = if args.flag_format == String::from("pkcs8") {
            let key_path = Path::new(&args.arg_keyfile);
            Signer::read_pk8(&key_path)?
        } else if args.flag_format == String::from("pem") {
            unimplemented!();
        } else if args.flag_format == String::from("bytes") {
            unimplemented!();
        } else if args.flag_format == String::from("new") {
            Signer::new()
        } else {
            return Err( ScalpelError::ArgumentError.context("File Format not recognized").into() )
        };
        // get signature
        let signature = keys.calculate_signature(path_victim)?;

        // create signed file
        concat::append_signature(&path_victim, &signature)?;

        // test the verification
        let signed_filename = concat::derive_output_filename(path_victim)?;
        keys.verify_file(Path::new(&signed_filename))?;

        info!("singing succeeded.");
        return Ok(())
    } else if args.cmd_cut {
        // command cut

        // do input handling
        let start = args.flag_start.unwrap_or(0) as u64; // if none, set to 0
        let size: u64 = if let Some(end) = args.flag_end {
            if let Some(_) = args.flag_size {
                return Err( ScalpelError::ArgumentError
                    .context("Either end or size has to be specified, not both").into());
            }
            if start >= end {
                return Err( ScalpelError::ArgumentError
                    .context(format!("end addr {1} should be larger than start addr {0}", start, end)).into());
            }
            end - start
        } else if let Some(size) = args.flag_size {
            size
        } else {
            return Err( ScalpelError::ArgumentError.context("Either end addr or size has to be specified").into());
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
            Err(e) => return Err(e),
        }
    }

    info!("scalpel operation complete");

    return Ok(())
}
