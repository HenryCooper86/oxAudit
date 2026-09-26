//! Small, shared persistence primitives for user-private application state.
//!
//! Writes are committed with an atomic rename, Unix permissions are kept
//! owner-only, and Unix reads/appends refuse to follow symbolic links.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use tempfile::NamedTempFile;

pub fn ensure_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create private directory: {error}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect private directory: {error}"))?;
    }

    Ok(())
}

pub(crate) fn read_to_string(path: &Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }

    let mut file = options.open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

pub(crate) fn open_private_append(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }

    let file = options
        .open(path)
        .map_err(|error| format!("cannot open private file: {error}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot protect private file: {error}"))?;
    }

    Ok(file)
}

pub(crate) fn atomic_write(path: &Path, content: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "private file path has no parent directory".to_string())?;
    ensure_private_dir(parent)?;

    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create temporary private file: {error}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot protect temporary private file: {error}"))?;
    }

    temporary
        .write_all(content)
        .map_err(|error| format!("cannot write temporary private file: {error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("cannot sync temporary private file: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("cannot replace private file: {}", error.error))?;

    #[cfg(unix)]
    let _ = File::open(parent).and_then(|directory| directory.sync_all());

    Ok(())
}
