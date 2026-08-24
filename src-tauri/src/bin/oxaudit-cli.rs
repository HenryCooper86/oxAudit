//! Thin process wrapper. Everything lives in `oxaudit_lib::cli` so the command
//! line can use the same internals as the desktop app rather than a public
//! subset of them.
//!
//! Deliberately without the `windows_subsystem = "windows"` attribute that
//! `main.rs` carries: the GUI must not spawn a console, and a CLI must have one.

fn main() {
    std::process::exit(oxaudit_lib::cli::run());
}
