#![no_main]
use libfuzzer_sys::fuzz_target;
use sflow_parser::SflowParser;

fuzz_target!(|data: &[u8]| {
    let parser = SflowParser::default();
    let _ = parser.parse_bytes(data);
});
