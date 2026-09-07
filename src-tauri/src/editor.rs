//! Typed, contained finding navigation. Stored scanner columns remain UTF-8 bytes.
use std::path::Path;

pub(crate) fn vscode_uri(
    root: &Path,
    path: &Path,
    line: u32,
    column: u32,
) -> Result<String, String> {
    use std::io::Read;
    if line == 0 || column == 0 {
        return Err("Finding line and column must be positive.".into());
    }
    // Bound both allocation and work, even for a file replaced since the scan.
    const MAX_BYTES: u64 = 8 * 1024 * 1024;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "Finding path escapes the captured root.")?;
    let file = crate::git_context::open_raw_file(root, relative)
        .map_err(|e| format!("Finding file is unavailable: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Finding path is not a file.".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("Editor position conversion is limited to files of 8 MiB.".into());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "The current file is not UTF-8; choose the system opener in Settings.")?;
    let current = text
        .lines()
        .nth((line - 1) as usize)
        .ok_or("The recorded line is no longer in the current file.")?;
    let byte_index = (column - 1) as usize;
    let prefix = current
        .get(..byte_index)
        .ok_or("The recorded byte column is no longer a character boundary in the current line.")?;
    let character_column = prefix.encode_utf16().count() + 1;
    let raw = path.to_str().ok_or("The finding path is not Unicode.")?;
    let encoded = encode_vscode_path(raw, cfg!(windows))?;
    Ok(format!("vscode://file{encoded}:{line}:{character_column}"))
}

fn encode_vscode_path(path: &str, windows: bool) -> Result<String, String> {
    let normalized;
    let raw = if windows {
        normalized = path
            .strip_prefix(r"\\?\")
            .unwrap_or(path)
            .replace('\\', "/");
        let bytes = normalized.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'/'
        {
            return Err("VS Code navigation supports local Windows drive paths; select the system opener for network/device paths.".into());
        }
        normalized.as_str()
    } else {
        path
    };
    let mut encoded = String::new();
    for (index, byte) in raw.bytes().enumerate() {
        if byte.is_ascii_alphanumeric()
            || b"/-._~".contains(&byte)
            || (windows && index == 1 && byte == b':')
        {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    if !encoded.starts_with('/') {
        encoded.insert(0, '/');
    }
    Ok(encoded)
}

/// Await launcher errors on Unix. Windows uses the opener's ShellExecuteExW
/// adapter (no cmd.exe/.cmd wrapper); the URI contains no raw filename syntax.
pub(crate) fn open_vscode(app: &tauri::AppHandle, uri: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url(uri, None::<String>)
            .map_err(|e| format!("VS Code could not be opened: {e}"))
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        let program = if cfg!(target_os = "macos") {
            "/usr/bin/open"
        } else {
            "xdg-open"
        };
        let output = std::process::Command::new(program)
            .arg(uri)
            .output()
            .map_err(|e| format!("VS Code URL handler could not be started: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err("VS Code URL handler is unavailable. Install/register VS Code, or select the system opener in Settings.".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_uri_preserves_spaces_reserved_characters_and_utf16_position() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let path = root.join("space 😀 #&%.js");
        std::fs::write(&path, "first\n😀é eval(input);\n").unwrap();
        let uri = vscode_uri(&root, &path, 2, 8).unwrap();
        assert!(uri.starts_with("vscode://file/"));
        assert!(
            uri.ends_with("space%20%F0%9F%98%80%20%23%26%25.js:2:5"),
            "{uri}"
        );
    }
    #[test]
    fn rejects_invalid_positions_removed_files_and_non_utf8_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let path = root.join("file.js");
        std::fs::write(&path, "😀eval(input)\n").unwrap();
        for (line, column, cause) in [
            (0, 1, "must be positive"),
            (1, 0, "must be positive"),
            (2, 1, "recorded line"),
            (1, 2, "character boundary"),
            (1, 200, "character boundary"),
        ] {
            let error = vscode_uri(&root, &path, line, column).unwrap_err();
            assert!(error.contains(cause), "{error}");
        }
        std::fs::remove_file(&path).unwrap();
        assert!(vscode_uri(&root, &path, 1, 1)
            .unwrap_err()
            .contains("Finding file is unavailable"));
    }
    #[test]
    fn contained_reads_reject_outside_paths_and_symlink_replacements() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        assert!(vscode_uri(&root, outside.path(), 1, 1)
            .unwrap_err()
            .contains("escapes the captured root"));
        #[cfg(unix)]
        {
            let replaced = root.join("replaced.js");
            std::os::unix::fs::symlink(outside.path(), &replaced).unwrap();
            assert!(vscode_uri(&root, &replaced, 1, 1)
                .unwrap_err()
                .contains("Finding file is unavailable"));
        }
    }
    #[test]
    fn conversion_is_bounded_and_rejects_invalid_utf8() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let file = root.join("app.js");
        std::fs::write(&file, [0xff, b'\n']).unwrap();
        assert!(vscode_uri(&root, &file, 1, 1)
            .unwrap_err()
            .contains("not UTF-8"));
        let handle = std::fs::File::create(&file).unwrap();
        handle.set_len(8 * 1024 * 1024 + 1).unwrap();
        assert!(vscode_uri(&root, &file, 1, 1)
            .unwrap_err()
            .contains("limited to files of 8 MiB"));
    }
    #[test]
    fn windows_uri_path_normalizes_drive_and_rejects_network_namespaces() {
        assert_eq!(
            encode_vscode_path(r"\\?\C:\project space\a#%.js", true).unwrap(),
            "/C:/project%20space/a%23%25.js"
        );
        assert!(encode_vscode_path(r"\\?\UNC\server\share\a.js", true).is_err());
        assert!(encode_vscode_path(r"\\server\share\a.js", true).is_err());
    }
    #[test]
    fn old_settings_default_to_system_and_unknown_editor_is_rejected() {
        let settings: crate::models::AppSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(serde_json::to_value(settings).unwrap()["editor"], "system");
        assert!(serde_json::from_str::<crate::models::AppSettings>(
            r#"{"editor":"shell-template"}"#
        )
        .is_err());
    }
}
