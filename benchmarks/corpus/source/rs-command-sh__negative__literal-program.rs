use std::process::Command;

pub fn listing() {
    // The program name is fixed at compile time.
    let _ = Command::new("sh").arg("-lc").arg("ls -la").status();
}
