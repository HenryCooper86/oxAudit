#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(pack) = oxaudit_scanners::RulePack::parse_toml(text) {
            let _ = pack.validate();
            let _ = oxaudit_scanners::CompiledRulePack::compile(pack);
        }
    }
});
