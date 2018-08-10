#[macro_use]
extern crate lazy_static;
extern crate regex;

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

mod signer;
use signer::*;

mod concat;
mod cut;
mod errors;
mod byte_offset;
use errors::*;
use byte_offset::*;

const USAGE: &'static str = "
scalpel

Usage:
  scalpel cut [--fragment=<fragment>] [--start=<start>] --end=<end> --output=<output> <file>
  scalpel cut [--fragment=<fragment>] [--start=<start>] --size=<size> --output=<output> <file>
  scalpel sign <keyfile> [--output=<output>] <file>
  scalpel sign <keyfile> <files..>
  scalpel (-h | --help)
  scalpel (-v |--version)

Commands:
  cut   extract bytes from a binary file
  sign  sign binary with a keypair such as ED25519 or RSA

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
    flag_start: Option<ByteOffset>,
    flag_end: Option<ByteOffset>,
    flag_size: Option<ByteOffset>,
    flag_fragment: Option<usize>,
    flag_output: Option<String>,
    arg_keyfile: String,
    arg_file: String,
    arg_files: Vec<String>,
    flag_format: Option<String>,
    flag_version: bool,
    flag_help: bool,
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const NAME: &'static str = env!("CARGO_PKG_NAME");

fn run() -> Result<()> {
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // check arguments
    if args.flag_version {
        println!("{} {}", NAME, VERSION);
        Ok(())
    } else if args.flag_help {
        println!("{}", USAGE);
        Ok(())
    } else if args.cmd_sign {
        // command sign

        let path_victim = Path::new(&args.arg_file);
        // get keys from the specified input file
        let key_format = args.flag_format.unwrap_or("pkcs8".to_string());
        let signer = match key_format.as_str() {
            "pkcs8" => {
                let key_path = Path::new(&args.arg_keyfile);
                Signer::from_pkcs8_file(&key_path)?
            }
            "pem" => {
                unimplemented!("can you suggest a parser?");
            }
            "generate" => Signer::random(),
            fmt => {
                return Err(ScalpelError::ArgumentError
                    .context(format!("File Format not recognized {}", fmt))
                    .into())
            }
        };
        // get signature
        let signature = signer.calculate_signature_of_file(path_victim)?;

        // create signed file
        concat::append_signature(&path_victim, &signature)?;

        if args.arg_files.len() > 0 {
            for item in args.arg_files.iter() {
                signer.verify_file(Path::new(item))?;
            }
        } else {
            // test the verification
            let signed_filename = args
                .flag_output
                .unwrap_or(concat::derive_output_filename(path_victim)?);

            signer.verify_file(Path::new(&signed_filename))?;

            info!("signing success: \"{}\"", signed_filename.as_str());
        }
        Ok(())
    } else if args.cmd_cut {
        // command cut

        // do input handling
        let start = args.flag_start.unwrap_or(Default::default()).as_u64(); // if none, set to 0
        let size: u64 = if let Some(end) = args.flag_end {
            if let Some(_) = args.flag_size {
                return Err(ScalpelError::ArgumentError
                    .context("Either end or size has to be specified, not both")
                    .into());
            }
            let end = end.as_u64();
            if start >= end {
                return Err(ScalpelError::ArgumentError
                    .context(format!(
                        "end addr {1} should be larger than start addr {0}",
                        start, end
                    ))
                    .into());
            }
            end - start
        } else if let Some(size) = args.flag_size {
            let size = size.as_u64();
            size
        } else {
            return Err(ScalpelError::ArgumentError
                .context("Either end addr or size has to be specified")
                .into());
        };
        let fragment_size = args.flag_fragment.unwrap_or(8192) as usize; // CHUNK from cut

        cut::cut_out_bytes(
            args.arg_file,
            args.flag_output.unwrap(),
            start,
            size,
            fragment_size,
        ).and_then(|_| {
            info!("Cutting success");
            Ok(())
        })
    } else {
        Err(ScalpelError::ArgumentError
            .context("No idea what you were thinking..")
            .into())
    }
}

quick_main!(run);
