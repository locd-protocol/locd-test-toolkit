#![no_main]
use libfuzzer_sys::fuzz_target;
use locd_verification::HelloMessage;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as verification message
    // Should never panic, only return Err
    let _ = HelloMessage::decode(data);
});
