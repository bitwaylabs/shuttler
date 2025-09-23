use bitcoin::Network;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "shuttler", version, author = "Side Labs")]
#[command(about = "A threshold vault signer of Side Bitcoin Bridge", long_about = None)]
pub struct Cli {
    #[clap(long, default_value = ".shuttler")]
    pub home: String,
    #[clap(long, default_value = "false")]
    pub mock: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init {
        #[clap(long, default_value = "5158")]
        port: u32,
        #[clap(long, default_value = "bitcoin")]
        network: Network    
    },
    /// Start a libp2p node
    Start {
        #[clap(long, default_value = "false")]
        relayer: bool,
        #[clap(long, default_value = "false")]
        bridge: bool,
        #[clap(long, default_value = "false")]
        lending: bool,
        #[clap(long, default_value = "false")]
        seed: bool,
    },   
    #[command(about = "Submit a bitcoin transaction to the sidechain")]
    SubmitTx {
        #[clap(long, default_value = "")]
        hash: String,
    },
    Address,
    Reset,
    Test {
        #[clap(long, default_value = "target/debug/shuttler")]
        bin: String,
        #[clap(long, default_value = "3")]
        n: u32,
        #[clap(long, default_value = "1")]
        tx: u32,
        #[clap(long, default_value = "2")]
        delay: u32,
        #[clap(long, default_value = "bridge")]
        module: String
    },
    Recover {
        #[clap(long, default_value = "target/debug/shuttler")]
        data: String,
    }
}

pub mod init;
pub mod start;
pub mod address;
pub mod reset;
pub mod submit_tx;
pub mod test;
pub mod recover;
