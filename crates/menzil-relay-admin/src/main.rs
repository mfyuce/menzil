//! `menzil-relay-admin`: see the library and `README.md`.

#[cfg(unix)]
mod agent;

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    agent::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("menzil-relay-admin runs on Unix only");
    std::process::exit(1);
}
