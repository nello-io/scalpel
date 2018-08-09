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

mod cut;
mod concat;
mod errors;
mod cmd_serialize;
use errors::*;
use cmd_serialize::serialize_cmd_opt;

const USAGE: &'static str = "
scalpel

Usage:
  scalpel cut [--fragment=<fragment>] [--start=<start>] --end=<end> --output=<output> <victimfile>
  scalpel cut [--fragment=<fragment>] [--start=<start>] --size=<size> --output=<output> <victimfile>
  scalpel sign <victimfile> <keyfile> [--format=<format>]
  scalpel (-h | --help)
  scalpel (-v |--version)

Commands:
  cut   extract bytes from a binary file
  sign  sign binary with ED25519 Key Pair

Options:
  -h --help                 Show this screen.
  -v --version              Show version.
  --start=<start>           Start byte offset of the section to cut out. If omitted, set to 0. Use Ki=1014, Mi=1024^2, Gi=1024^3 and K=10^3, M=10^6, G=10^9 as suffix.
  --end=<end>               The end byte offset which will not be included. Use Ki=1014, Mi=1024^2, Gi=1024^3 and K=10^3, M=10^6, G=10^9 as suffix.
  --size=<size>             Alternate way to sepcify the <end> combined with start. Use Ki=1014, Mi=1024^2, Gi=1024^3 and K=10^3, M=10^6, G=10^9 as suffix.
  --fragment=<fragment>     Define the size of the fragment/chunk to read/write at once. Use Ki=1014, Mi=1024^2, Gi=1024^3 and K=10^3, M=10^6, G=10^9 as suffix.
  --format=<format>         specify the key format, eihter pkcs8, pem, bytes or new
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_cut: bool,
    cmd_sign: bool,
    flag_start: Option<String>,
    flag_end: Option<String>,
    flag_size: Option<String>,
    flag_fragment: Option<String>,
    flag_output: String,
    arg_victimfile: String,
    arg_keyfile: String,
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

        let path_victim = Path::new(&args.arg_victimfile);
        // get keys from the specified input file
        let key_format = args.flag_format.unwrap_or("pkcs8".to_string());
        let signer = match key_format.as_str() {
            "pkcs8" => {
                let key_path = Path::new(&args.arg_keyfile);
                Signer::from_pkcs8_file(&key_path)?
            }
            "pem" => {
                unimplemented!();
            }
            "raw" => {
                unimplemented!();
            }
            "generate" => Signer::random(),
            fmt => {
                return Err(
                    ScalpelError::ArgumentError
                        .context(format!("File Format not recognized {}", fmt))
                        .into(),
                )
            }
        };
        // get signature
        let signature = signer.calculate_signature_of_file(path_victim)?;

        // create signed file
        concat::append_signature(&path_victim, &signature)?;

        // test the verification
        let signed_filename = concat::derive_output_filename(path_victim)?;
        signer.verify_file(Path::new(&signed_filename))?;

        info!("signing success: \"{}\"", signed_filename.as_str());

        Ok(())
    } else if args.cmd_cut {
        // command cut

        // do input handling
        let start = serialize_cmd_opt(args.flag_start.unwrap_or("0".to_string()) )?; // if none, set to 0
        let size: u64 = if let Some(end) = args.flag_end {
            let end = serialize_cmd_opt(end)?;
            if let Some(_) = args.flag_size {
                return Err(
                    ScalpelError::ArgumentError
                        .context("Either end or size has to be specified, not both")
                        .into(),
                );
            }
            if start >= end {
                return Err(
                    ScalpelError::ArgumentError
                        .context(format!(
                            "end addr {1} should be larger than start addr {0}",
                            start,
                            end
                        ))
                        .into(),
                );
            }
            end - start
        } else if let Some(size) = args.flag_size {
            serialize_cmd_opt(size)?
        } else {
            return Err(
                ScalpelError::ArgumentError
                    .context("Either end addr or size has to be specified")
                    .into(),
            );
        };
        let fragment_size = serialize_cmd_opt(args.flag_fragment.unwrap_or("8192".to_string()))?; // CHUNK from cut

        cut::cut_out_bytes(
            args.arg_victimfile,
            args.flag_output,
            start,
            size,
            fragment_size as usize,
        ).and_then(|_| {
            info!("Cutting success");
            Ok(())
        })
    } else {
        Err(ScalpelError::ArgumentError.context("No idea what you were thinking..").into())
    }
}

quick_main!(run);
