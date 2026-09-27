#![no_main]

use libfuzzer_sys::fuzz_target;
use tetherd::protocol::cipher::CipherState;

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];
    let mut cipher = CipherState::new(&key, *b"FUZ1");
    let _ = cipher.open(data);
});
