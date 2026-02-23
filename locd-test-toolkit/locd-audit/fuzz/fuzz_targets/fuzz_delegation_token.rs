#![no_main]
use libfuzzer_sys::fuzz_target;
use locd_delegation::DelegationToken;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as delegation token
    // Should never panic, only return Err
    let _ = DelegationToken::from_cbor(data);
});
