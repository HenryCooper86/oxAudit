//! Windows raw-file capability. Validate the object actually opened before any
//! bytes are read; pathname checks alone cannot prevent junction replacement.
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Git raw file escaped its captured root or is a reparse point",
    )
}

fn final_path(file: &File) -> io::Result<PathBuf> {
    // Windows extended paths are bounded to 32,767 UTF-16 code units. Fail closed
    // if a driver reports a larger path; never truncate a containment comparison.
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: file owns a live handle and buffer has the supplied writable size.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= buffer.len() {
        return Err(denied());
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn open_plain(path: &Path, directory: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        // Hold the captured root and opened object against delete/rename while
        // validating. Ordinary readers/writers remain allowed.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        )
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(denied());
    }
    Ok(file)
}

pub(super) fn open_raw_file(root: &Path, relative: &Path) -> io::Result<File> {
    let root_handle = open_plain(root, true)?;
    let captured_root = final_path(&root_handle)?;
    // `root` is already canonicalized by discovery. Do not canonicalize again
    // here: that would authorize an ancestor replaced after the earlier checks.
    if captured_root != root {
        return Err(denied());
    }
    let expected = captured_root.join(relative);
    let file = open_plain(&expected, false)?;
    let opened_path = final_path(&file)?;
    // Exact component-path equality additionally rejects an ancestor redirected
    // to another directory inside the checkout, not only an outside junction.
    if opened_path != expected
        || !opened_path.starts_with(&captured_root)
        || final_path(&root_handle)? != captured_root
    {
        return Err(denied());
    }
    Ok(file)
}
