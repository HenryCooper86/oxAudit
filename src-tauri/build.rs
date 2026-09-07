// MSVC manifest workaround adapted from Tauri's examples/api/src-tauri/build.rs.
// Copyright 2019-2024 Tauri Programme within The Commons Conservancy.
// Used under Apache-2.0. See NOTICE and docs/getting-started.md.
fn main() {
    let msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if msvc {
        // A resource manifest on the app alone does not reach the library test
        // harness. Use one linker manifest for every MSVC executable, including
        // that harness, without duplicating Tauri's application resource.
        tauri_build::try_build(
            tauri_build::Attributes::new()
                .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest()),
        )
        .expect("Tauri build failed");
        let manifest = std::path::PathBuf::from(
            std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"),
        )
        .join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        println!("cargo:rustc-link-arg=/WX");
    } else {
        tauri_build::build();
    }
}
