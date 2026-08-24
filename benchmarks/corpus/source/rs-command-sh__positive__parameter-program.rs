use std::process::Command;

pub fn run(user_supplied: &str) {
    let _ = Command::new("sh").arg("-lc").arg(user_supplied).status();
}
