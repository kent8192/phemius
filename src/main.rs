use clap::Parser;
use phemius::cli::{Cli, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Cli::parse()).await
}
