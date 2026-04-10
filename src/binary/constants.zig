pub const BinaryError = error{
    BufferTooSmall,
    InvalidVarint,
    InvalidUtf8,
    CompressionError,
    InvalidFormat,
    WriteFailed,
    ReadFailed,
    InvalidToken,
    EndOfStream,
    InvalidLength,
    TokenNotFound,
};

pub const LIST_EMPTY: u8 = 0;
pub const DICTIONARY_0: u8 = 236;
pub const DICTIONARY_1: u8 = 237;
pub const DICTIONARY_2: u8 = 238;
pub const DICTIONARY_3: u8 = 239;
pub const INTEROP_JID: u8 = 245;
pub const FB_JID: u8 = 246;
pub const AD_JID: u8 = 247;
pub const LIST_8: u8 = 248;
pub const LIST_16: u8 = 249;
pub const JID_PAIR: u8 = 250;
pub const HEX_8: u8 = 251;
pub const BINARY_8: u8 = 252;
pub const BINARY_20: u8 = 253;
pub const BINARY_32: u8 = 254;
pub const NIBBLE_8: u8 = 255;
pub const PACKED_MAX: u8 = 127;
