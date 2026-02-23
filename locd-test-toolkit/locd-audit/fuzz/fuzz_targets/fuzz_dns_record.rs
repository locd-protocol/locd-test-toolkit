#![no_main]
use libfuzzer_sys::fuzz_target;
use locd_dns::IdentityRecord;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as DNS TXT record
    // Should never panic, only return Err
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = IdentityRecord::from_txt_record(s);
    }
});
