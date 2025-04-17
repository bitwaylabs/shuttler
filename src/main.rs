use clap::Parser;
use shuttler::commands::{
    address, init, reset, start, test,
    submit_header, submit_tx, Cli, Commands};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Initialize tracing with customization
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { port, network } => {
            init::execute(&cli.home, port.to_owned(), network.to_owned());
        }
        Commands::Start {relayer,seed, bridge, lending } => {
            start::execute(&cli.home, relayer, bridge, lending, seed).await;
        }
        Commands::Address => {
            address::execute(&cli.home);
        }
        Commands::Reset => {
            reset::execute(&cli.home);
        }
        Commands::SubmitHeader { height } => {
            submit_header::execute(&cli.home, height).await;
        }
        Commands::SubmitTx { hash} => {
            submit_tx::execute(&cli.home, &hash).await;
        }
        Commands::Test {bin, n, tx, delay, module} => {
            test::execute(bin.clone().leak(), n, tx, delay, module).await;
        }
    }
}
