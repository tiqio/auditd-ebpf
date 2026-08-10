mod commands;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    commands::Cli::parse().run()
}
