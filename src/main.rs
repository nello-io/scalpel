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
extern crate rand;

use docopt::Docopt;
use std::path::{PathBuf, Path};

mod signer;
use signer::*;

mod concat;
mod cut;
mod errors;
mod byte_offset;
mod stitch;
mod graft;
use errors::*;
use byte_offset::*;

const USAGE: &'static str = "
scalpel

Usage:
  scalpel cut [--fragment=<fragment>] [--start=<start>] --end=<end> --output=<output> <file>
  scalpel cut [--fragment=<fragment>] [--start=<start>] --size=<size> --output=<output> <file>
  scalpel sign <keyfile> [--output=<output>] [--format=<format>] <file>
  scalpel sign <keyfile> <files>...
  scalpel stitch (--binary=<binary> --offset=<offset>)... --output=<output> [--fill-pattern=<fill_pattern>]
  scalpel graft [--start=<start>] --end=<end> --graft=<graft> --output=<output> <input> [--fill-pattern=<fill_pattern>]
  scalpel graft [--start=<start>] --size=<size> --graft=<graft> --output=<output> <input> [--fill-pattern=<fill_pattern>]
  scalpel (-h | --help)
  scalpel (-v |--version)

Commands:
  cut       extract bytes from a binary file
  sign      sign binary with a keypair such as ED25519 or RSA
  stitch    stitchs binaries together, each file starts at <offset> with random padding
  graft     replace a section with <graft> specfied by start and end/size

Options:
  -h --help                     Show this screen.
  -v --version                  Show version.
  --start=<start>               Start byte offset of the section to cut out. If omitted, set to 0.
  --end=<end>                   The end byte offset which will not be included.
  --size=<size>                 Alternate way to sepcify the <end> combined with start.
  --fragment=<fragment>         Define the size of the fragment/chunk to read/write at once. [Default: 8192]
  --format=<format>             Specify the key format, eihter pkcs8, pem, bytes or new
  --fill-pattern=<fill_patern>  Specify padding style for stitching (random|one|zero)
  --graft=<graft>               file which replaces the original part
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_cut: bool,
    cmd_sign: bool,
    cmd_stitch: bool,
    cmd_graft: bool,
    flag_start: Option<ByteOffset>,
    flag_end: Option<ByteOffset>,
    flag_size: Option<ByteOffset>,
    flag_fragment: Option<ByteOffset>,
    flag_output: Option<String>,
    flag_binary: Vec<PathBuf>,
    arg_keyfile: String,
    arg_file: String,
    arg_files: Vec<String>,
    arg_input: PathBuf,
    flag_offset: Vec<ByteOffset>,
    flag_fill_pattern: Option<stitch::FillPattern>,
    flag_format: Option<String>,
    flag_graft: PathBuf,
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

        // get keys from the specified input file
        let key_format = args.flag_format.unwrap_or("pkcs8".to_string());
        let signer = match key_format.as_str() {
            "pkcs8" => {
                let key_path = &args.arg_keyfile.as_ref();
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
        
        if args.arg_files.len() > 0 {
            for item in args.arg_files.iter() {
                // get signature
                let signature = signer.calculate_signature_of_file(item)?;
                // create signed file
                concat::append_signature(item.as_ref(), &signature)?;

                // verify
                let signed_filename = concat::derive_output_filename(Path::new(item))?;
                signer.verify_file(&signed_filename)?;
                info!("signing success: \"{}\"", &signed_filename.as_str());
            }
        } else {
            let path_victim = &args.arg_file.as_ref();
            // get signature
            let signature = signer.calculate_signature_of_file(path_victim)?;

            // create signed file
            concat::append_signature(path_victim, &signature)?;

            // test the verification
            let signed_filename = args
                .flag_output
                .unwrap_or(concat::derive_output_filename(path_victim)?);

            signer.verify_file(&signed_filename)?;

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
        let fragment_size = args.flag_fragment.unwrap_or(Default::default()).as_u64(); // CHUNK 8192 from cut
        
        cut::cut_out_bytes(
            args.arg_file,
            args.flag_output.unwrap(),
            start,
            size,
            fragment_size as usize,
        ).and_then(|_| {
            info!("Cutting success");
            Ok(())
        })
    } else if args.cmd_stitch {
        // command stitch binaries together
        
        stitch::stitch_files(args.flag_binary, args.flag_offset, args.flag_output.unwrap(), args.flag_fill_pattern.unwrap_or_default() )?;

        Ok(())
    } else if args.cmd_graft {
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

        graft::graft_file(args.flag_graft, args.arg_input, args.flag_output.unwrap(), start, size, args.flag_fill_pattern.unwrap_or_default())?;

        Ok(())
    } else {
        Err(ScalpelError::ArgumentError
            .context("No idea what you were thinking..")
            .into())
    }
}

quick_main!(run);
