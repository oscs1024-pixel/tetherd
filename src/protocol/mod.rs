pub mod cipher;
pub mod frame;
pub mod handshake;
pub mod message;
pub mod transport;

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 4096;
pub const MAX_CONTROL_REQUEST_BYTES: usize = 512 * 1024;
pub const MAX_CONTROL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
