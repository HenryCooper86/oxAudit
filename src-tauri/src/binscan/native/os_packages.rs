//! The operating-system package layer inside extracted filesystem images.
//!
//! Binary signatures and ELF package notes both look at individual binaries.
//! A container image or firmware filesystem carries something better: its own
//! package database — `/var/lib/dpkg/status`, `/lib/apk/db/installed` — an
//! exact, builder-declared inventory of every installed package and version.
//! This module reads those databases and the `os-release` that names the
//! distribution, so an image with stripped binaries but an intact package
//! database still gets OS-level advisory matching instead of nothing.
//!
//! The distribution identity is **required**, and it comes only from an
//! `os-release` member in the same image: `Debian:12`, not a guessed `Debian`.
//! OSV's ecosystems are release-keyed, and the package databases never say
//! which release they belong to. No identity means the packages are still
//! reported as components — the inventory is real — with a note saying why
//! they were not asked about.

/// Cap on packages read from one database: the largest real images carry
/// hundreds; a crafted database cannot flood the detection list.
pub const MAX_PACKAGES_PER_DATABASE: usize = 10_000;

/// The distribution identity an image declared, reduced to the one thing
/// advisory matching needs: OSV's release-qualified ecosystem name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroIdentity {
    pub osv_ecosystem: String,
}

/// What reading a member that looks like `os-release` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsReleaseMatch {
    NotOsRelease,
    /// Parsed as os-release, but not a distribution OSV carries — with the
    /// reason a run should state out loud.
    Unsupported(String),
    Distro(DistroIdentity),
}

/// Member paths that carry identity or package inventory. Suffix matches,
/// because virtual member paths are container-prefixed
/// (`image.tar!/layer.tar!/etc/os-release`).
pub fn is_os_release_path(path: &str) -> bool {
    path.ends_with("etc/os-release") || path.ends_with("usr/lib/os-release")
}

pub fn is_dpkg_status_path(path: &str) -> bool {
    path.ends_with("var/lib/dpkg/status")
}

pub fn is_apk_installed_path(path: &str) -> bool {
    path.ends_with("lib/apk/db/installed")
}

/// Debian release codenames → OSV's release-qualified ecosystems. `sid` and
/// `testing` name a moving target no dump pins, so they are unsupported
/// rather than mapped to the last stable.
const DEBIAN_CODENAMES: [(&str, &str); 4] = [
    ("buster", "Debian:10"),
    ("bullseye", "Debian:11"),
    ("bookworm", "Debian:12"),
    ("trixie", "Debian:13"),
];

/// Read an `os-release` member and decide which OSV ecosystem it names.
///
/// Ubuntu maps to the standard-archive ecosystem: `Ubuntu:<release>:LTS` for
/// LTS releases (`YY.04` in an even year) and `Ubuntu:<release>` for interim
/// ones (OSV's `Ubuntu:23.10`). The `Ubuntu:Pro:…` ecosystems hold only ESM
/// fixes — queried against OSV, `openssl` in 22.04 has 96 advisories under
/// `Ubuntu:22.04:LTS` and none under `Ubuntu:Pro:22.04:LTS` — and an image
/// built from the public archive does not carry ESM packages.
///
/// Alpine's `VERSION_ID` is the patch release (`3.20.3`); OSV keys the branch
/// (`Alpine:v3.20`), so only major.minor is kept.
pub fn parse_os_release(bytes: &[u8]) -> OsReleaseMatch {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return OsReleaseMatch::NotOsRelease,
    };
    let mut fields: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        fields.insert(key.trim().to_string(), value.to_string());
    }
    let Some(id_raw) = fields.get("ID") else {
        return OsReleaseMatch::NotOsRelease;
    };
    let id = id_raw.to_ascii_lowercase();
    let version_id = fields.get("VERSION_ID").cloned().unwrap_or_default();
    let codename = fields.get("VERSION_CODENAME").cloned().unwrap_or_default();

    match id.as_str() {
        "debian" => {
            // The codename is authoritative; VERSION_ID agrees with it when
            // both are present.
            if let Some((_, ecosystem)) =
                DEBIAN_CODENAMES.iter().find(|(name, _)| *name == codename)
            {
                return OsReleaseMatch::Distro(DistroIdentity {
                    osv_ecosystem: ecosystem.to_string(),
                });
            }
            match version_id.as_str() {
                "10" | "11" | "12" | "13" => {
                    let major = version_id.as_str();
                    OsReleaseMatch::Distro(DistroIdentity {
                        osv_ecosystem: format!("Debian:{major}"),
                    })
                }
                _ => OsReleaseMatch::Unsupported(format!(
                    "os-release names Debian without a supported release (codename {codename:?}, version {version_id:?}); packages are reported but not matched against a distribution"
                )),
            }
        }
        "ubuntu" => match ubuntu_ecosystem(&version_id) {
            Some(osv_ecosystem) => OsReleaseMatch::Distro(DistroIdentity { osv_ecosystem }),
            None => OsReleaseMatch::Unsupported(format!(
                "os-release names Ubuntu without a recognizable release (version {version_id:?}); packages are reported but not matched against a distribution"
            )),
        },
        "alpine" => match alpine_branch(&version_id) {
            Some(branch) => OsReleaseMatch::Distro(DistroIdentity {
                osv_ecosystem: format!("Alpine:v{branch}"),
            }),
            None => OsReleaseMatch::Unsupported(format!(
                "os-release names Alpine without a release branch (version {version_id:?}); packages are reported but not matched against a distribution"
            )),
        },
        other => OsReleaseMatch::Unsupported(format!(
            "os-release names {other:?}, which OSV does not carry as a distribution ecosystem; packages are reported but not matched"
        )),
    }
}

/// `YY.MM` → `Ubuntu:YY.MM:LTS` for April releases of even years, otherwise
/// `Ubuntu:YY.MM`. Anything not shaped like a release is `None`.
fn ubuntu_ecosystem(version_id: &str) -> Option<String> {
    let (year, month) = version_id.split_once('.')?;
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if !numeric(year) || month.len() != 2 || !numeric(month) {
        return None;
    }
    let lts = month == "04" && year.parse::<u32>().ok()? % 2 == 0;
    Some(if lts {
        format!("Ubuntu:{version_id}:LTS")
    } else {
        format!("Ubuntu:{version_id}")
    })
}

/// `3.20.3` → `3.20`. `edge` and other non-numeric versions are `None`:
/// OSV has no ecosystem for a rolling branch.
fn alpine_branch(version_id: &str) -> Option<String> {
    let mut parts = version_id.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    (numeric(major) && numeric(minor)).then(|| format!("{major}.{minor}"))
}

/// `/var/lib/dpkg/status`: Debian control stanzas. Only packages whose
/// Status says `install ok installed` are installed; `deinstall ok
/// config-files` is a leftover, not inventory.
pub fn parse_dpkg_status(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    for stanza in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut installed = false;
        for line in stanza.lines() {
            if let Some(rest) = line.strip_prefix("Package:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Version:") {
                version = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Status:") {
                installed = rest.trim() == "install ok installed";
            }
            if packages.len() >= MAX_PACKAGES_PER_DATABASE {
                return packages;
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            if installed && !name.is_empty() && !version.is_empty() {
                packages.push((name, version));
            }
        }
    }
    packages
}

/// `/lib/apk/db/installed`: one blank-line-separated block per package with
/// single-letter keys — `P:` is the name, `V:` the version.
pub fn parse_apk_installed(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    for block in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("P:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("V:") {
                version = Some(rest.trim().to_string());
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            if !name.is_empty() && !version.is_empty() {
                packages.push((name, version));
                if packages.len() >= MAX_PACKAGES_PER_DATABASE {
                    return packages;
                }
            }
        }
    }
    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_paths_match_by_suffix_across_containers() {
        assert!(is_os_release_path("image.tar!/layer.tar!/etc/os-release"));
        assert!(is_os_release_path("rootfs.squashfs!/usr/lib/os-release"));
        assert!(!is_os_release_path("etc/os-release.txt"));
        assert!(is_dpkg_status_path("img.tar!/var/lib/dpkg/status"));
        assert!(!is_dpkg_status_path("var/lib/dpkg/status-old"));
        assert!(is_apk_installed_path("img.tar!/lib/apk/db/installed"));
        assert!(is_apk_installed_path("img.tar!/usr/lib/apk/db/installed"));
        assert!(!is_apk_installed_path("lib/apk/db/installed.lock"));
    }

    #[test]
    fn debian_os_release_maps_by_codename_then_version() {
        let bookworm = b"ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n";
        assert_eq!(
            parse_os_release(bookworm),
            OsReleaseMatch::Distro(DistroIdentity {
                osv_ecosystem: "Debian:12".into()
            })
        );
        // No codename; the numeric release decides.
        let bullseye = b"ID=debian\nVERSION_ID=11\n";
        assert_eq!(
            parse_os_release(bullseye),
            OsReleaseMatch::Distro(DistroIdentity {
                osv_ecosystem: "Debian:11".into()
            })
        );
        // sid is a moving target: stated, not guessed.
        let sid = b"ID=debian\nVERSION_CODENAME=sid\n";
        assert!(matches!(
            parse_os_release(sid),
            OsReleaseMatch::Unsupported(_)
        ));
    }

    fn ecosystem_of(os_release: &[u8]) -> String {
        match parse_os_release(os_release) {
            OsReleaseMatch::Distro(identity) => identity.osv_ecosystem,
            other => panic!("expected a distribution, got {other:?}"),
        }
    }

    #[test]
    fn ubuntu_and_alpine_map_to_release_qualified_ecosystems() {
        // Standard (non-Pro) archive: OSV's `Ubuntu:<release>:LTS` carries
        // main-archive fixes such as openssl; the Pro ecosystem does not.
        assert_eq!(
            ecosystem_of(b"ID=ubuntu\nVERSION_ID=\"24.04\"\n"),
            "Ubuntu:24.04:LTS"
        );
        assert_eq!(
            ecosystem_of(b"ID=alpine\nVERSION_ID=3.20\n"),
            "Alpine:v3.20"
        );
        assert!(matches!(
            parse_os_release(b"ID=alpine\n"),
            OsReleaseMatch::Unsupported(_)
        ));
    }

    #[test]
    fn real_alpine_os_release_maps_to_the_major_minor_branch() {
        // The os-release Alpine actually ships: VERSION_ID carries the patch
        // release, OSV keys the branch.
        let alpine = b"NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\nHOME_URL=\"https://alpinelinux.org/\"\nBUG_REPORT_URL=\"https://gitlab.alpinelinux.org/alpine/aports/-/issues\"\n";
        assert_eq!(ecosystem_of(alpine), "Alpine:v3.20");
        assert_eq!(
            ecosystem_of(b"ID=alpine\nVERSION_ID=3.9.6\n"),
            "Alpine:v3.9"
        );
        assert!(matches!(
            parse_os_release(b"ID=alpine\nVERSION_ID=edge\n"),
            OsReleaseMatch::Unsupported(_)
        ));
    }

    #[test]
    fn real_ubuntu_os_release_maps_lts_and_interim_releases() {
        let jammy = b"PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=jammy\n";
        assert_eq!(ecosystem_of(jammy), "Ubuntu:22.04:LTS");
        assert_eq!(
            ecosystem_of(b"ID=ubuntu\nVERSION_ID=\"20.04\"\n"),
            "Ubuntu:20.04:LTS"
        );
        // Interim releases carry no LTS suffix in OSV (`Ubuntu:23.10`).
        assert_eq!(
            ecosystem_of(b"ID=ubuntu\nVERSION_ID=\"23.10\"\n"),
            "Ubuntu:23.10"
        );
        assert_eq!(
            ecosystem_of(b"ID=ubuntu\nVERSION_ID=\"23.04\"\n"),
            "Ubuntu:23.04"
        );
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

    #[test]
    fn debian_buster_is_a_supported_osv_release() {
        assert_eq!(
            ecosystem_of(b"ID=debian\nVERSION_ID=\"10\"\nVERSION_CODENAME=buster\n"),
            "Debian:10"
        );
        assert_eq!(ecosystem_of(b"ID=debian\nVERSION_ID=10\n"), "Debian:10");
    }

    #[test]
    fn unsupported_distributions_and_non_os_release_members_say_so() {
        assert!(matches!(
            parse_os_release(b"ID=fedora\nVERSION_ID=40\n"),
            OsReleaseMatch::Unsupported(_)
        ));
        assert_eq!(
            parse_os_release(b"\x7fELF\x02\x01\x01"),
            OsReleaseMatch::NotOsRelease
        );
        assert_eq!(
            parse_os_release(b"NAME=Something\n"),
            OsReleaseMatch::NotOsRelease
        );
    }

    #[test]
    fn dpkg_status_yields_only_installed_packages() {
        let status = b"Package: libc6\nVersion: 2.36-9+deb12u3\nStatus: install ok installed\nArchitecture: amd64\n\nPackage: leftbehind\nVersion: 1.0-1\nStatus: deinstall ok config-files\n\nPackage: noversion\nStatus: install ok installed\n";
        let packages = parse_dpkg_status(status);
        assert_eq!(
            packages,
            vec![("libc6".to_string(), "2.36-9+deb12u3".to_string())]
        );
    }

    #[test]
    fn apk_installed_yields_name_version_pairs() {
        let db = b"P:musl\nV:1.2.5-r0\nI:1048576\nT:the musl c library\n\nP:busybox\nV:1.36.1-r7\n\nP:noversion\n";
        let packages = parse_apk_installed(db);
        assert_eq!(
            packages,
            vec![
                ("musl".to_string(), "1.2.5-r0".to_string()),
                ("busybox".to_string(), "1.36.1-r7".to_string()),
            ]
        );
    }

    #[test]
    fn package_databases_are_bounded() {
        let stanza = "Package: p\nVersion: 1\nStatus: install ok installed\n\n";
        let huge = stanza.repeat(MAX_PACKAGES_PER_DATABASE + 50);
        assert_eq!(
            parse_dpkg_status(huge.as_bytes()).len(),
            MAX_PACKAGES_PER_DATABASE
        );
    }
}
