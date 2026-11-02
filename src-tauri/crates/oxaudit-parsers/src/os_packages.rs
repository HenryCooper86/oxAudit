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

/// rpm's SQLite database, at its real location: Fedora-era images move it to
/// `/usr/lib/sysimage/rpm` and leave `/var/lib/rpm` as a symlink, which the
/// extractor does not follow, so both paths are matched.
pub fn is_rpmdb_sqlite_path(path: &str) -> bool {
    path.ends_with("var/lib/rpm/rpmdb.sqlite")
        || path.ends_with("usr/lib/sysimage/rpm/rpmdb.sqlite")
}

/// rpm's older Berkeley DB hash database (RHEL 7 and 8, Amazon Linux 2;
/// openSUSE Leap up to 15.2 keeps it under sysimage).
pub fn is_rpmdb_bdb_path(path: &str) -> bool {
    path.ends_with("var/lib/rpm/Packages") || path.ends_with("usr/lib/sysimage/rpm/Packages")
}

/// rpm's NDB database (openSUSE Leap 15.3+, SLE 15 SP3+), which is not read.
pub fn is_rpmdb_ndb_path(path: &str) -> bool {
    path.ends_with("var/lib/rpm/Packages.db") || path.ends_with("usr/lib/sysimage/rpm/Packages.db")
}

/// The write-ahead log beside an rpm SQLite database.
pub fn is_rpmdb_wal_path(path: &str) -> bool {
    path.strip_suffix("-wal").is_some_and(is_rpmdb_sqlite_path)
}

/// The OSV ecosystems one image identity is asked about.
///
/// Red Hat files each release differently, and an image does not record
/// which repository a package came from, so a RHEL identity is asked about
/// every ecosystem its packages can be filed under (checked against OSV's
/// Red Hat dump):
///
/// - RHEL 8 and 9: the `::baseos`, `::appstream` and `::crb` streams;
/// - RHEL 6 and 7: the `::server` variant, which images are built on;
/// - RHEL 10 onwards: the minor release itself (`10.0`), already the
///   identity, with no streams.
///
/// Every other identity is one ecosystem.
pub fn osv_query_ecosystems(ecosystem: &str) -> Vec<String> {
    let streams: &[&str] = match ecosystem.strip_prefix("Red Hat:enterprise_linux:") {
        Some("8" | "9") => &["baseos", "appstream", "crb"],
        Some("6" | "7") => &["server"],
        _ => return vec![ecosystem.to_string()],
    };
    streams
        .iter()
        .map(|stream| format!("{ecosystem}::{stream}"))
        .collect()
}

/// Whether a distribution's OSV records name the source package (Debian's
/// `glibc`, Rocky's `openssl`) rather than the installed binary package.
/// Checked against OSV: Red Hat and AlmaLinux name binary RPMs
/// (`openssl-libs`); every other distribution mapped here names the source.
pub fn files_advisories_under_source(ecosystem: &str) -> bool {
    let family = ecosystem.split(':').next().unwrap_or(ecosystem);
    !matches!(family, "Red Hat" | "AlmaLinux")
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
        "rhel" => {
            // RHEL 6 to 9 are filed by major (and stream or variant); RHEL
            // 10 onwards by minor release. Older majors are left unsupported
            // rather than guessed.
            let major = release_major(&version_id).and_then(|major| major.parse::<u32>().ok());
            let minor = version_id
                .split_once('.')
                .map(|(_, minor)| minor)
                .filter(|minor| !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()));
            match (major, minor) {
                (Some(major @ 6..=9), _) => OsReleaseMatch::Distro(DistroIdentity {
                    osv_ecosystem: format!("Red Hat:enterprise_linux:{major}"),
                }),
                (Some(major @ 10..), Some(minor)) => OsReleaseMatch::Distro(DistroIdentity {
                    osv_ecosystem: format!("Red Hat:enterprise_linux:{major}.{minor}"),
                }),
                _ => unrecognized_release(id_raw, &version_id),
            }
        }
        "rocky" | "almalinux" | "azurelinux" => {
            let family = match id.as_str() {
                "rocky" => "Rocky Linux",
                "almalinux" => "AlmaLinux",
                _ => "Azure Linux",
            };
            match release_major(&version_id) {
                Some(major) => OsReleaseMatch::Distro(DistroIdentity {
                    osv_ecosystem: format!("{family}:{major}"),
                }),
                None => unrecognized_release(id_raw, &version_id),
            }
        }
        "opensuse-leap" => match alpine_branch(&version_id) {
            Some(release) => OsReleaseMatch::Distro(DistroIdentity {
                osv_ecosystem: format!("openSUSE:Leap {release}"),
            }),
            None => unrecognized_release(id_raw, &version_id),
        },
        "openeuler" => {
            // `VERSION="22.03 (LTS-SP4)"` → `openEuler:22.03-LTS-SP4`.
            let version = fields.get("VERSION").map(String::as_str).unwrap_or_default();
            let qualifier = version
                .split_once('(')
                .and_then(|(_, rest)| rest.strip_suffix(')'))
                .map(str::trim)
                .filter(|q| !q.is_empty() && q.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
            match alpine_branch(&version_id) {
                Some(release) => OsReleaseMatch::Distro(DistroIdentity {
                    osv_ecosystem: match qualifier {
                        Some(qualifier) => format!("openEuler:{release}-{qualifier}"),
                        None => format!("openEuler:{release}"),
                    },
                }),
                None => unrecognized_release(id_raw, &version_id),
            }
        }
        // CBL-Mariner 2.0 is filed as Azure Linux 2 (checked against OSV);
        // there is no ecosystem for 1.0.
        "mariner" => match release_major(&version_id).as_deref() {
            Some("2") => OsReleaseMatch::Distro(DistroIdentity {
                osv_ecosystem: "Azure Linux:2".into(),
            }),
            _ => unrecognized_release(id_raw, &version_id),
        },
        // A rolling release: one ecosystem whatever the snapshot date.
        "opensuse-tumbleweed" => OsReleaseMatch::Distro(DistroIdentity {
            osv_ecosystem: "openSUSE:Tumbleweed".into(),
        }),
        "sles" | "sled" => OsReleaseMatch::Unsupported(format!(
            "os-release names {id_raw:?}; OSV files SUSE Linux Enterprise advisories under product modules the image does not name, so packages are reported but not matched"
        )),
        other => OsReleaseMatch::Unsupported(format!(
            "os-release names {other:?}, which OSV does not carry as a distribution ecosystem; packages are reported but not matched"
        )),
    }
}

/// `9.4` → `9`, `3.0` → `3`, `9` → `9`. Anything not starting with a
/// numeric major is `None`.
fn release_major(version_id: &str) -> Option<String> {
    let major = version_id.split('.').next()?;
    (!major.is_empty() && major.bytes().all(|b| b.is_ascii_digit())).then(|| major.to_string())
}

fn unrecognized_release(id: &str, version_id: &str) -> OsReleaseMatch {
    OsReleaseMatch::Unsupported(format!(
        "os-release names {id:?} without a recognizable release (version {version_id:?}); packages are reported but not matched against a distribution"
    ))
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

/// One installed package from an OS package database.
///
/// The source package is kept because that is what most distributions file
/// advisories under: Debian's `glibc` covers the `libc6` binary, Alpine's
/// `openssl` origin covers `libcrypto3`. Asking OSV about the binary name of
/// a package built from a differently named source answers nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsPackage {
    /// The installed (binary) package name.
    pub name: String,
    pub version: String,
    /// The source package (dpkg `Source:`) or origin (apk `o:`) it was built
    /// from, when the database names one.
    pub source_name: Option<String>,
    /// The source version, when dpkg records one that differs from the
    /// binary's (a binNMU rebuild such as `+b1`).
    pub source_version: Option<String>,
}

/// `/var/lib/dpkg/status`: Debian control stanzas. Only packages whose
/// Status says `install ok installed` are installed; `deinstall ok
/// config-files` is a leftover, not inventory. `Source:` is either `name` or
/// `name (version)`; absent, the source is the package itself.
pub fn parse_dpkg_status(bytes: &[u8]) -> Vec<OsPackage> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    for stanza in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut source = None;
        let mut installed = false;
        for line in stanza.lines() {
            if let Some(rest) = line.strip_prefix("Package:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Version:") {
                version = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Source:") {
                source = dpkg_source(rest);
            } else if let Some(rest) = line.strip_prefix("Status:") {
                installed = rest.trim() == "install ok installed";
            }
            if packages.len() >= MAX_PACKAGES_PER_DATABASE {
                return packages;
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            if installed && !name.is_empty() && !version.is_empty() {
                let (source_name, source_version) = source.unzip();
                packages.push(OsPackage {
                    name,
                    version,
                    source_name,
                    source_version: source_version.flatten(),
                });
            }
        }
    }
    packages
}

/// `glibc` or `glibc (2.36-9+deb12u4)`. A malformed value names no source,
/// so the package falls back to its own name rather than a guess.
fn dpkg_source(value: &str) -> Option<(String, Option<String>)> {
    let value = value.trim();
    let (name, version) = match value.split_once(char::is_whitespace) {
        None => (value, None),
        Some((name, rest)) => {
            let version = rest
                .trim()
                .strip_prefix('(')
                .and_then(|rest| rest.strip_suffix(')'))
                .map(str::trim)
                .filter(|version| !version.is_empty() && !version.contains(char::is_whitespace))?;
            (name, Some(version.to_string()))
        }
    };
    (!name.is_empty()).then(|| (name.to_string(), version))
}

/// `/lib/apk/db/installed`: one blank-line-separated block per package with
/// single-letter keys — `P:` is the name, `V:` the version, `o:` the origin
/// (source) package.
pub fn parse_apk_installed(bytes: &[u8]) -> Vec<OsPackage> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    for block in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut origin = None;
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("P:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("V:") {
                version = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("o:") {
                origin = Some(rest.trim().to_string()).filter(|origin| !origin.is_empty());
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            if !name.is_empty() && !version.is_empty() {
                packages.push(OsPackage {
                    name,
                    version,
                    source_name: origin,
                    source_version: None,
                });
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
    }

    #[test]
    fn debian_buster_is_a_supported_osv_release() {
        assert_eq!(
            ecosystem_of(b"ID=debian\nVERSION_ID=\"10\"\nVERSION_CODENAME=buster\n"),
            "Debian:10"
        );
        assert_eq!(ecosystem_of(b"ID=debian\nVERSION_ID=10\n"), "Debian:10");
    }

    fn distro(os_release: &str) -> Option<String> {
        match parse_os_release(os_release.as_bytes()) {
            OsReleaseMatch::Distro(identity) => Some(identity.osv_ecosystem),
            _ => None,
        }
    }

    #[test]
    fn rpm_distros_map_to_their_osv_ecosystems() {
        let cases = [
            ("ID=\"rhel\"\nVERSION_ID=\"9.4\"\n", Some("Red Hat:enterprise_linux:9")),
            ("ID=\"rhel\"\nVERSION_ID=\"8.10\"\n", Some("Red Hat:enterprise_linux:8")),
            ("ID=\"rhel\"\nVERSION_ID=\"7.9\"\n", Some("Red Hat:enterprise_linux:7")),
            ("ID=\"rhel\"\nVERSION_ID=\"6.10\"\n", Some("Red Hat:enterprise_linux:6")),
            // RHEL 10 is filed by minor release, with no content streams.
            ("ID=\"rhel\"\nVERSION_ID=\"10.0\"\n", Some("Red Hat:enterprise_linux:10.0")),
            ("ID=\"rhel\"\nVERSION_ID=\"10\"\n", None),
            ("ID=\"rhel\"\nVERSION_ID=\"5.11\"\n", None),
            ("ID=\"rocky\"\nVERSION_ID=\"9.4\"\n", Some("Rocky Linux:9")),
            ("ID=\"almalinux\"\nVERSION_ID=\"8.9\"\n", Some("AlmaLinux:8")),
            ("ID=\"opensuse-leap\"\nVERSION_ID=\"15.5\"\n", Some("openSUSE:Leap 15.5")),
            ("ID=azurelinux\nVERSION_ID=\"3.0\"\n", Some("Azure Linux:3")),
            (
                "NAME=\"openEuler\"\nVERSION=\"22.03 (LTS-SP4)\"\nID=\"openEuler\"\nVERSION_ID=\"22.03\"\n",
                Some("openEuler:22.03-LTS-SP4"),
            ),
            ("ID=\"openEuler\"\nVERSION=\"24.03 (LTS)\"\nVERSION_ID=\"24.03\"\n", Some("openEuler:24.03-LTS")),
            ("ID=\"openEuler\"\nVERSION=\"24.09\"\nVERSION_ID=\"24.09\"\n", Some("openEuler:24.09")),
            // Rejected shapes stay unsupported rather than guessed.
            ("ID=\"rocky\"\nVERSION_ID=\"nine\"\n", None),
            ("ID=\"rhel\"\n", None),
            // SUSE files SLES advisories under product modules the image does
            // not name; Fedora, Amazon, Oracle, CentOS, Photon and Mariner
            // have no OSV distribution ecosystem.
            ("ID=\"sles\"\nVERSION_ID=\"15.5\"\n", None),
            ("ID=fedora\nVERSION_ID=40\n", None),
            ("ID=\"amzn\"\nVERSION_ID=\"2023\"\n", None),
            ("ID=\"ol\"\nVERSION_ID=\"9.4\"\n", None),
            ("ID=\"centos\"\nVERSION_ID=\"7\"\n", None),
            ("ID=photon\nVERSION_ID=5.0\n", None),
            // CBL-Mariner 2.0 is filed as Azure Linux 2 (checked against OSV);
            // 1.0 has no ecosystem.
            ("ID=mariner\nVERSION_ID=2.0\n", Some("Azure Linux:2")),
            ("ID=mariner\nVERSION_ID=1.0\n", None),
            ("ID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20251030\"\n", Some("openSUSE:Tumbleweed")),
        ];
        for (os_release, expected) in cases {
            assert_eq!(distro(os_release).as_deref(), expected, "{os_release:?}");
        }
    }

    #[test]
    fn rhel_queries_both_content_streams() {
        assert_eq!(
            osv_query_ecosystems("Red Hat:enterprise_linux:9"),
            [
                "Red Hat:enterprise_linux:9::baseos",
                "Red Hat:enterprise_linux:9::appstream",
                "Red Hat:enterprise_linux:9::crb"
            ]
        );
        assert_eq!(
            osv_query_ecosystems("Red Hat:enterprise_linux:8"),
            [
                "Red Hat:enterprise_linux:8::baseos",
                "Red Hat:enterprise_linux:8::appstream",
                "Red Hat:enterprise_linux:8::crb"
            ]
        );
        // RHEL 6 and 7 are filed by variant; images are built on Server.
        assert_eq!(
            osv_query_ecosystems("Red Hat:enterprise_linux:7"),
            ["Red Hat:enterprise_linux:7::server"]
        );
        assert_eq!(
            osv_query_ecosystems("Red Hat:enterprise_linux:6"),
            ["Red Hat:enterprise_linux:6::server"]
        );
        assert_eq!(
            osv_query_ecosystems("Red Hat:enterprise_linux:10.0"),
            ["Red Hat:enterprise_linux:10.0"]
        );
        // Everything else, including an already stream-qualified name, is
        // asked about as given.
        assert_eq!(osv_query_ecosystems("Rocky Linux:9"), ["Rocky Linux:9"]);
        assert_eq!(
            osv_query_ecosystems("Red Hat:enterprise_linux:9::baseos"),
            ["Red Hat:enterprise_linux:9::baseos"]
        );
        assert_eq!(osv_query_ecosystems("Red Hat"), ["Red Hat"]);
    }

    #[test]
    fn source_naming_follows_the_distribution() {
        // Checked against OSV: Red Hat and AlmaLinux records name binary RPMs
        // (`openssl-libs`); the rest name the source package (`openssl`).
        for binary in [
            "Red Hat:enterprise_linux:9",
            "Red Hat:enterprise_linux:9::baseos",
            "AlmaLinux:9",
        ] {
            assert!(!files_advisories_under_source(binary), "{binary}");
        }
        for source in [
            "Debian:12",
            "Ubuntu:22.04:LTS",
            "Alpine:v3.20",
            "Rocky Linux:9",
            "openSUSE:Leap 15.5",
            "Azure Linux:3",
            "Azure Linux:2",
            "openSUSE:Tumbleweed",
            "openEuler:22.03-LTS-SP4",
        ] {
            assert!(files_advisories_under_source(source), "{source}");
        }
    }

    #[test]
    fn rpm_database_paths_match_their_real_locations() {
        assert!(is_rpmdb_sqlite_path("layer.tar!/var/lib/rpm/rpmdb.sqlite"));
        assert!(is_rpmdb_sqlite_path("usr/lib/sysimage/rpm/rpmdb.sqlite"));
        assert!(!is_rpmdb_sqlite_path("var/lib/rpm/rpmdb.sqlite-wal"));
        assert!(is_rpmdb_wal_path("var/lib/rpm/rpmdb.sqlite-wal"));
        assert!(!is_rpmdb_sqlite_path("home/me/rpmdb.sqlite"));
        assert!(is_rpmdb_bdb_path("layer.tar!/var/lib/rpm/Packages"));
        // openSUSE Leap ≤15.2 keeps its Berkeley DB under sysimage.
        assert!(is_rpmdb_bdb_path("usr/lib/sysimage/rpm/Packages"));
        assert!(is_rpmdb_ndb_path("usr/lib/sysimage/rpm/Packages.db"));
        assert!(is_rpmdb_ndb_path("var/lib/rpm/Packages.db"));
        assert!(!is_rpmdb_ndb_path("srv/Packages.db"));
        assert!(!is_rpmdb_bdb_path("var/lib/rpm/Packages.db"));
        assert!(!is_rpmdb_bdb_path("srv/www/Packages"));
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
        assert_eq!(packages, vec![pkg("libc6", "2.36-9+deb12u3", None, None)]);
    }

    fn pkg(
        name: &str,
        version: &str,
        source_name: Option<&str>,
        source_version: Option<&str>,
    ) -> OsPackage {
        OsPackage {
            name: name.to_string(),
            version: version.to_string(),
            source_name: source_name.map(str::to_string),
            source_version: source_version.map(str::to_string),
        }
    }

    #[test]
    fn dpkg_status_reads_source_names_and_versions() {
        // Debian's advisories are filed under the source package, and a binNMU
        // rebuild gives the binary a version the source never had.
        let status = b"Package: libc6\nSource: glibc (2.36-9+deb12u4)\nVersion: 2.36-9+deb12u4+b1\nStatus: install ok installed\n\nPackage: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n\nPackage: bash\nVersion: 5.2.15-2+b2\nStatus: install ok installed\n";
        assert_eq!(
            parse_dpkg_status(status),
            vec![
                pkg(
                    "libc6",
                    "2.36-9+deb12u4+b1",
                    Some("glibc"),
                    Some("2.36-9+deb12u4")
                ),
                pkg("libssl3", "3.0.11-1~deb12u2", Some("openssl"), None),
                pkg("bash", "5.2.15-2+b2", None, None),
            ]
        );
    }

    #[test]
    fn apk_installed_reads_origins() {
        let db = b"P:libcrypto3\nV:3.1.4-r5\no:openssl\n\nP:musl\nV:1.2.5-r0\no:musl\n\nP:busybox\nV:1.36.1-r7\n";
        assert_eq!(
            parse_apk_installed(db),
            vec![
                pkg("libcrypto3", "3.1.4-r5", Some("openssl"), None),
                pkg("musl", "1.2.5-r0", Some("musl"), None),
                pkg("busybox", "1.36.1-r7", None, None),
            ]
        );
    }

    #[test]
    fn apk_installed_yields_name_version_pairs() {
        let db = b"P:musl\nV:1.2.5-r0\nI:1048576\nT:the musl c library\n\nP:busybox\nV:1.36.1-r7\n\nP:noversion\n";
        let packages = parse_apk_installed(db);
        assert_eq!(
            packages,
            vec![
                pkg("musl", "1.2.5-r0", None, None),
                pkg("busybox", "1.36.1-r7", None, None),
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
