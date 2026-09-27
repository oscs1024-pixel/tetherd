pub mod cipher;
pub mod frame;
pub mod handshake;
pub mod message;

pub const PROTOCOL_VERSION: u16 = 1;

// Protocol surfaces use separate ceilings so an authenticated peer cannot force
// allocations sized for the much larger local UDS response path.
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 4 * 1024;
pub const MAX_PEER_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_CONTROL_REQUEST_BYTES: usize = 512 * 1024;
pub const MAX_CONTROL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXEC_OUTPUT_BYTES: usize = 1024 * 1024;
