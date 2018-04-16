use failure::Error;

use std;
pub type Result<X> = std::result::Result<X, Error>;

#[derive(Debug, Fail)]
pub enum SigningError {
    #[fail(display = "Failed to open.")]
    OpeningError,

    #[fail(display = "Failed to read.")]
    ReadingError,

    #[fail(display = "Failed to write.")]
    WritingError,

    #[fail(display = "Failed to resolve Path")]
    PathError,
}