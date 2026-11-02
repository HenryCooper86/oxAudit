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
        // Every ecosystem an RPM image is asked about, after RHEL's identity
        // expands into its content streams.
        for os_release in [
            &b"ID=\"rhel\"\nVERSION_ID=\"9.4\"\n"[..],
            b"ID=\"rocky\"\nVERSION_ID=\"9.4\"\n",
            b"ID=\"almalinux\"\nVERSION_ID=\"9.4\"\n",
            b"ID=\"opensuse-leap\"\nVERSION_ID=\"15.5\"\n",
            b"ID=azurelinux\nVERSION_ID=\"3.0\"\n",
            b"ID=mariner\nVERSION_ID=2.0\n",
            b"ID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20251030\"\n",
            b"ID=\"openEuler\"\nVERSION=\"22.03 (LTS-SP4)\"\nVERSION_ID=\"22.03\"\n",
        ] {
            for ecosystem in osv_query_ecosystems(&ecosystem_of(os_release)) {
                assert_eq!(
                    crate::advisories::versioning::family_for("ECOSYSTEM", &ecosystem),
                    Some(crate::advisories::versioning::VersionFamily::Rpm),
                    "{ecosystem} must compare as rpm"
                );
            }
        }
    }
}
