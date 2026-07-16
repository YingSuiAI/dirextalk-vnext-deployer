#![forbid(unsafe_code)]

use clap::Parser;
use dirextalk_vnext_deployer::{Cli, run};

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("dirextalk-vnext-deployer: {error}");
        std::process::exit(1);
    }
}
