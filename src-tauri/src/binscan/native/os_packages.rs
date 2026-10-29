//! Moved to the `oxaudit-parsers` crate so the package-database parsers can
//! be fuzzed without any GUI dependency; re-exported here so the binary
//! scanner's internal paths keep reading as one module tree.
pub use oxaudit_parsers::os_packages::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn ecosystem_of(os_release: &[u8]) -> String {
        match parse_os_release(os_release) {
            OsReleaseMatch::Distro(identity) => identity.osv_ecosystem,
            other => panic!("expected a distribution, got {other:?}"),
        }
    }

    /// The ecosystems os-release maps to must stay ones the advisory version
    /// comparison understands, or matching would silently skip them.
    #[test]
    fn os_release_ecosystems_stay_comparable() {
        let jammy = b"PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=jammy\n";
        for ecosystem in [
            ecosystem_of(jammy),
            ecosystem_of(b"ID=ubuntu\nVERSION_ID=23.10\n"),
        ] {
            assert!(
                crate::advisories::versioning::family_for("ECOSYSTEM", &ecosystem).is_some(),
                "{ecosystem} must stay comparable"
            );
        }
        assert!(crate::advisories::versioning::family_for(
            "ECOSYSTEM",
            &ecosystem_of(b"ID=alpine\nVERSION_ID=3.20.3\n")
        )
        .is_some());
    }
}
