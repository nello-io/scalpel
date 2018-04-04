//#[cfg(feature = "v2")]
//use super::v2::proto::sub::SubPacketType;

//#[cfg(feature = "v2")]
//use super::v2::proto::{PacketVersion, SubPacketVersion};

// subpacket and major version
pub type PacketVersion = u16;
pub type SubPacketVersion = u16;

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
#[repr(u16)]
pub enum SubPacketType {
    ForceReset = 2,
    ForceWipe = 3,

    ConfigurationCheckpointQuery = 5,
    ConfigurationCheckpointRequestCurrent = 7,
    ConfigurationCheckpointRetryCurrent = 8,
    ConfigurationCheckpointSkipCurrent = 9,

    ReportIpAddress = 11,
    ReportMacAddress = 12,
    ReportSuperCapVoltage = 13,
    ReportConfigurationData = 14,
    ReportBacktrace = 15,
    ReportUptime = 16,
    ReportResetReason = 17,
    ReportFirmwareVersion = 18,
    ReportChipId = 19,
    ReportRSSI = 20,

    GeoFenceActivate = 65,
    GeoFenceDeactivate = 66,
    GeoFenceStatus = 67,

    TimeWindowActivate = 128,
    TimeWindowDeactivate = 129,
    TimeWindowStatus = 130,

    BellRingDetected = 100,

    Ping = 501,
    Pong = 502,

    Dummy = 0xffff,
}

pub use failure::Error;

use std;
pub type Result<X> = std::result::Result<X, Error>;

#[derive(Debug, Fail)]
pub enum ParsingError {
    #[cfg(feature = "v2")]
    #[fail(display = "Invalid PacketVersion: `{}`", version)]
    InvalidVersion { version: PacketVersion },

    #[fail(display = "Signature verification error")]
    SignatureVerfification,

    #[fail(display = "Encoding error")]
    EncodePacket,

    #[fail(display = "Decoding error")]
    DecodePacket,

    #[cfg(feature = "v2")]
    #[fail(display = "Failed to decode sub packet")]
    DecodeSubPacket,

    #[cfg(feature = "v2")]
    #[fail(display = "Unknown Sub Packet Type `{}`", ty_raw)]
    InvalidSubPacketType { ty_raw: u16},

    #[cfg(feature = "v2")]
    #[fail(display = "Unhandled Version {:?} for `{:?}`", version, ty)]
    InvalidSubPacketVersion { ty: SubPacketType, version : SubPacketVersion },

    #[cfg(feature = "v2")]
    #[fail(display = "Invalid SubPacket Length of {} for `{:?}`", length, ty)]
    InvalidSubPacketLength { ty: SubPacketType , length : usize},


    #[cfg(feature = "v2")]
    #[fail(display = "Faile to decodeSubPacket")]
    ParseSubPacket,

    #[cfg(feature = "v2")]
    #[fail(display = "PackageParsing error: `{}`", reason)]
    ParsePacket { reason: String },

    #[cfg(feature = "v2")]
    #[fail(display = "Outer frame and inner frame length mismatch: `{}` vs `{}`", length_inner,
           length_outer)]
    ParsePacketLengthConflict {
        length_inner: usize,
        length_outer: usize,
    },

    #[fail(display = "Failed to convert")]
    Conversion,

    #[fail(display = "Failed to map: `{}`", why)]
    Unmapped { why: String },

    #[fail(display = "Failed to do some crypto: `{}`", reason)]
    Crypto { reason: String },

    #[fail(display = "Failed to do add/remove padding: `{}`", why)]
    Padding { why: String },

    #[fail(display = "Misc shit: `{}`", reason)]
    Misc { reason: String },
}
