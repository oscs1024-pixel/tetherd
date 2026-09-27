#![no_main]

use libfuzzer_sys::fuzz_target;
use tetherd::protocol::message::Message;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Message>(data);
});
