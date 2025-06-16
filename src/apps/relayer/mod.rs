

use std::time::Duration;

use bitcoincore_rpc::{Auth, Client};
use ed25519_compact::SecretKey;
use futures::join;
use crate::{config::Config, helper::{client_fee_provider::FeeProviderClient, client_ordinals::OrdinalsClient, encoding::pubkey_to_identifier}};

pub mod bridge;
pub mod lending;

#[derive(Debug)]
pub struct Relayer {
    // deprecated
    config: Config,
    pub bitcoin_client: Client,
    pub ordinals_client: OrdinalsClient,
    pub fee_provider_client: FeeProviderClient,
    pub db_relayer: sled::Db,
    pub ticker: tokio::time::Interval,
    pub identifier: frost_adaptor_signature::Identifier,
}

impl Relayer {
    pub fn new(conf: Config) -> Self {

        let auth = if !conf.bitcoin.user.is_empty() {
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone())
        } else {
            Auth::None
        };

        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc, 
            auth,
        ).expect("Could not initial bitcoin RPC client");

        let ordinals_client = OrdinalsClient::new(&conf.ordinals.endpoint);
        let fee_provider_client = FeeProviderClient::new(&conf.fee_provider);

        let db_relayer = sled::open(conf.get_database_with_name("relayer")).expect("Counld not create database!");
        let ticker = tokio::time::interval(Duration::from_secs(conf.loop_interval as u64));


        // load private key from priv_validator_key_path
        let priv_validator_key = conf.load_validator_key();

        let mut b = priv_validator_key
            .priv_key
            .ed25519_signing_key()
            .unwrap()
            .as_bytes()
            .to_vec();
        b.extend(priv_validator_key.pub_key.to_bytes());
        let node_key = SecretKey::new(b.as_slice().try_into().unwrap());
        let identifier = pubkey_to_identifier(node_key.public_key().as_slice());

        Self {
            // priv_validator_key: validator_key,
            bitcoin_client,
            ordinals_client,
            fee_provider_client,
            config: conf,
            db_relayer,
            ticker,
            identifier
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub async fn start(&self) {
        join!(
            bridge::start_relayer_tasks(self),
            lending::start_relayer_tasks(self),
        );
    }
}
