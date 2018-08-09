#[macro_use]
extern crate lazy_static;
extern crate regex;
use regex::{Regex,Captures};

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
use errors::*;

use std::fmt;

#[derive(Debug)]
enum Magnitude {
    Unit,
    K,
    Ki,
    M,
    Mi,
    G,
    Gi,
}

impl Default for Magnitude {
    fn default() -> Self {
        Magnitude::Unit
    }
}

impl Magnitude {
    pub fn parse(mag_str: &str) -> Result<Self> {
        match mag_str {
            "" => Ok(Magnitude::Unit),
            "K" => Ok(Magnitude::K),
            "Ki" => Ok(Magnitude::Ki),
            "M" => Ok(Magnitude::M),
            "Mi" => Ok(Magnitude::Mi),
            "G" => Ok(Magnitude::G),
            "Gi" => Ok(Magnitude::Gi),
            _ => {
                debug!("No idea what to do with {} as magnitude ", mag_str);
                Err(ScalpelError::ParsingError.into())
            },
        }
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            Magnitude::Unit => 1u64,
            Magnitude::K => 1000u64,
            Magnitude::Ki => 1024u64,
            Magnitude::M => 1000u64*1000u64,
            Magnitude::Mi => 1024u64*1024u64,
            Magnitude::G => 1000u64*1000u64*1000u64,
            Magnitude::Gi => 1024u64*1024u64*1024u64,
        }
    }
}


// unused, untested
//
// impl<'de> serde::de::Deserialize<'de> for Magnitude {
//     fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
//     where
//         D: serde::de::Deserializer<'de>,
//     {
//         struct MagnitudeVisitor;

//         impl<'de> serde::de::Visitor<'de> for MagnitudeVisitor {
//             type Value = Magnitude;

//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("Expected a magnitude")
//             }

//             fn visit_str<E>(self, value: &str) -> ::std::result::Result<Magnitude, E>
//             where
//                 E: serde::de::Error,
//             {
//                 Magnitude::parse(value).map_err(|_e| {
//                     serde::de::Error::unknown_field(value, MAGNITUDES)
//                 })
//             }
//         }
//         const MAGNITUDES: &'static [&'static str] = &["", "K", "Ki", "G", "Gi", "M", "Mi"];
//         deserializer.deserialize_enum("Magnitude", MAGNITUDES, MagnitudeVisitor)
//     }
// }

#[derive(Debug, Default)]
struct ByteOffset {
    num: u64,
    magnitude: Magnitude,
}

impl ByteOffset {
    pub fn new(num: u64, magnitude: Magnitude) -> Self {
        Self { num, magnitude }
    }
    pub fn as_u64(&self) -> u64 {
        self.magnitude.as_u64() * self.num
    }
}

impl<'de> serde::de::Deserialize<'de> for ByteOffset {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {

        struct ByteOffsetVisitor;

        impl<'de> serde::de::Visitor<'de> for ByteOffsetVisitor {
            type Value = ByteOffset;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Expected a ByteOffset")
            }

            fn visit_str<E>(self, value: &str) -> ::std::result::Result<ByteOffset, E>
            where
                E: serde::de::Error,
            {
                lazy_static!{
                    static ref REGEX : Regex = Regex::new(r"^([0-9]+)((?:[KMGTE]i?)?)$").unwrap();
                }
                
                let byte_offset = REGEX.captures(value).ok_or(Err::<Captures,ScalpelError>(ScalpelError::ParsingError.into()))
                .and_then(|captures| {
                    if captures.len() == 3 {
                        let num_str = &captures[1];
                        let magnitude_str = &captures[2];
                        let num : u64 = num_str.parse::<u64>().map_err(|_e| Err::<u64,ScalpelError>(ScalpelError::ParsingError) ).expect("u64 parsing exploded");;
                        let magnitude = Magnitude::parse(magnitude_str).expect("magnitude exploded");
                        Ok(ByteOffset::new(num, magnitude))
                    } else {
                        Ok(Default::default())
                    }
                }).expect("Captures exploded");
                Ok(byte_offset)
            }

        }
        deserializer.deserialize_str(ByteOffsetVisitor)
    }
}

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
                return Err(ScalpelError::ArgumentError
                    .context(format!("File Format not recognized {}", fmt))
                    .into())
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
            args.arg_victimfile,
            args.flag_output,
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
