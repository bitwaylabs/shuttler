use bitcoin::{bip32::{DerivationPath, Xpriv}, key::Secp256k1, Address, CompressedPublicKey, Network, PrivateKey, TapNodeHash};
use bip39::{self, Mnemonic};
use cosmos_sdk_proto::cosmos::auth::v1beta1::{query_client::QueryClient as AuthQueryClient, BaseAccount, QueryAccountRequest};

use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};
use serde::{Deserialize, Serialize};
use tendermint_config::PrivValidatorKey;
use std::{fs, path::PathBuf, str::FromStr, sync::Mutex};
use crate::helper::cipher::random_bytes;

const CONFIG_FILE: &str = "config.toml";

use lazy_static::lazy_static;

pub mod candidate;
pub mod keys;

pub use keys::*;

lazy_static! {
    static ref PRIV_VALIDATOR_KEY: Mutex<Option<PrivValidatorKey>> = Mutex::new(None);
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = {
        Mutex::new(None)
    };
}

fn default_rpc() -> String{
    format!("127.0.0.1:6780")
}

fn default_max_peers() -> usize {
    10
}

/// Threshold Signature Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(skip_serializing, skip_deserializing)]
    pub home: PathBuf,
    // libp2p port
    pub port: u32,
    pub enable_rpc: bool,
    #[serde(default = "default_rpc")]
    pub rpc_address: String,
    pub bootstrap_nodes: Vec<String>,
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    /// logger level
    pub log_level: String,
    pub mnemonic: String,
    pub priv_validator_key_path: String,

    pub bitcoin: BitcoinCfg,
    pub bitway: CosmosChain,
    
    pub ordinals: OrdinalsCfg,
    pub fee_provider: FeeProviderCfg,

    pub relay_runes: bool,

    pub last_scanned_height_bitway: u64,
    pub last_scanned_height_bitcoin: u64,

    pub loop_interval: u64,
    pub batch_relayer_count: u64,

    pub max_attempts: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultKeypair {
    pub priv_key: KeyPackage,
    pub pub_key: PublicKeyPackage,
    pub tweak: Option<TapNodeHash>,
}

/// Bitcoin Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BitcoinCfg {
    /// Bitcoin network type
    pub network: Network,
    /// Bitcoin RPC endpoint
    pub rpc: String,
    /// RPC User
    pub user: String,
    /// RPC password
    pub password: String,
}

/// Side Chain Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CosmosChain {
    /// the cosmos grpc endpoint, http://localhost:9001
    pub grpc: String,
    pub rpc: String,
    /// Transaction gas
    pub gas: usize,
    pub fee: Fee,
}

/// Ordinals Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrdinalsCfg {
    /// Ord API endpoint
    pub endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FeeProviderCfg {
    pub submit_fee_rate: bool,
    pub fetch_fee_rate_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fee {
    pub amount: usize,
    pub denom: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnyKey {
    pub r#type: String,
    pub value: String,
}

/// relayer account will be used to sign transactions on the side chain,
/// such as sending block headers, depositing and withdrawing transactions
pub async fn get_relayer_account(conf: &Config) -> BaseAccount {

    let cache = BASE_ACCOUNT.lock().unwrap().clone().map(|account| account);
    match cache {
        Some(account) => {
            let new_account  = account.clone();
            // new_account.sequence += 1;
            // BASE_ACCOUNT.lock().unwrap().replace(new_account.clone());
            return new_account;
        }
        None => {
            let mut client = AuthQueryClient::connect(conf.bitway.grpc.clone()).await.unwrap();
            let request = QueryAccountRequest {
                // address: conf.signer_cosmos_address().to_string(),
                address: conf.relayer_bitcoin_address()
            };
    
            match client.account(request).await {
                Ok(response) => {
    
                    let base_account: BaseAccount = response.into_inner().account.unwrap().to_msg().unwrap();
                    // BASE_ACCOUNT.lock().unwrap().replace(base_account.clone());
                    base_account
                }
                Err(e) => {
                    panic!("\n Relayer account don't exist on side chain: {e} ");
                }
            }
        }
    }
}

pub fn save_relayer_account(account: &BaseAccount) {
    BASE_ACCOUNT.lock().unwrap().replace(account.clone());
}

pub fn remove_relayer_account() {
    *BASE_ACCOUNT.lock().unwrap() = None;
}

impl Config {
    pub fn load_validator_key(&self) -> PrivValidatorKey {
        let priv_key_path = if self.priv_validator_key_path.starts_with("/") {
            PathBuf::from(self.priv_validator_key_path.clone())
        } else {
            self.home.join(self.priv_validator_key_path.clone())
        };
        let text = fs::read_to_string(priv_key_path.clone()).expect("priv_validator_key.json does not exists!");
    
        let prv_key = serde_json::from_str::<PrivValidatorKey>(text.as_str()).expect("Failed to parse priv_validator_key.json");
        // PRIV_VALIDATOR_KEY.lock().unwrap().replace(prv_key.clone());
        prv_key
            
    }

    pub fn from_file(app_home: &str) -> Result<Self, std::io::Error> {
        
        let home = if app_home.starts_with("/") {
            PathBuf::from(app_home)
        } else {
            home_dir(app_home)
        };
        if !home.join(CONFIG_FILE).exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Config file not found",
            ));
        }
        let contents = fs::read_to_string(home.join(CONFIG_FILE))?;
        let mut config: Config = toml::from_str(&contents).expect("Failed to parse config file");
        config.home = home;

        Ok(config)
    }

    pub fn generate_priv_validator_key(home: PathBuf) {
        let rng = rand::thread_rng();
        let sk = ed25519_consensus::SigningKey::new(rng);
        let priv_key = tendermint::private_key::PrivateKey::from_ed25519_consensus(sk);

        let key = tendermint_config::PrivValidatorKey {
            address: tendermint::account::Id::from(priv_key.public_key()),
            pub_key: priv_key.public_key(),
            priv_key,
        };

        fs::create_dir_all(&home).unwrap();
        let text= serde_json::to_string_pretty(&key).unwrap();
        fs::write(home.join("priv_validator_key.json"), text).unwrap();
    }

    pub fn default(home_str: &str, port: u32, network: Network) -> Self {
        let entropy = random_bytes(32);
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_slice()).expect("failed to create mnemonic");
        // let p2p_keypair = to_base64(libp2p::identity::Keypair::generate_ed25519().to_protobuf_encoding().unwrap().as_slice());
        let home =  if home_str.starts_with("/") {
            PathBuf::from_str(home_str).unwrap()
        } else {
            home_dir(home_str)
        };
        Self::generate_priv_validator_key(home.clone());
        Self {
            home,
            // p2p_keypair ,
            port: port as u32,
            enable_rpc: false,
            rpc_address: default_rpc(),
            bootstrap_nodes: vec![],
            max_peers: default_max_peers(),
            log_level: "debug".to_string(),
            mnemonic: mnemonic.to_string(),
            priv_validator_key_path: "priv_validator_key.json".to_string(),
            bitcoin: BitcoinCfg {
                network,
                rpc: "http://192.248.150.102:18332".to_string(),
                user: "side".to_string(),
                password: "12345678".to_string(),
            },
            bitway: CosmosChain {
                grpc: "http://localhost:9090".to_string(),
                rpc: "http://localhost:26657".to_owned(),
                gas: 1000000,
                fee: Fee {
                    amount: 1000,
                    denom: "uside".to_string(),
                },
            },
            ordinals: OrdinalsCfg {
                endpoint: "".to_string(),
            },
            fee_provider: FeeProviderCfg {
                submit_fee_rate: false,
                fetch_fee_rate_url: "https://mempool.space/testnet/api/v1/fees/recommended".to_string(),
            },
            relay_runes: false,
            // tweaks: BTreeMap::new(),
            last_scanned_height_bitway: 0,
            last_scanned_height_bitcoin: 0,
            loop_interval: 60,
            batch_relayer_count: 10,
            max_attempts: 5,
        }
    }

    pub fn to_string(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn websocket_endpoint(&self) -> String {
        format!("{}/websocket", self.bitway.rpc.replace("http", "ws") )
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        if !self.home.exists() {
            fs::create_dir_all(&self.home)?;
        }
        let contents = self.to_string();
        fs::write(self.home.join(CONFIG_FILE), contents)
    }

    pub fn relayer_bitcoin_privkey(&self) -> PrivateKey {
        // Replace with your mnemonic and HD path
        let hd_path = DerivationPath::from_str("m/84'/0'/0'/0/0").expect("invalid HD path");
        // Generate seed from mnemonic
        let mnemonic = Mnemonic::from_str(&self.mnemonic).expect("Invalid mnemonic");

        // Derive HD key
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(self.bitcoin.network, &mnemonic.to_seed("")).expect("failed to create master key");
        master.derive_priv(&secp, &hd_path).expect("Failed to derive key").to_priv()

    }

    pub fn relayer_bitcoin_pubkey(&self) -> CompressedPublicKey {
        let secp = Secp256k1::new();
        CompressedPublicKey::from_private_key(&secp, &self.relayer_bitcoin_privkey()).expect("failed to derive pubkey")
    }

    pub fn relayer_bitcoin_address(&self) -> String {
        let pubkey = self.relayer_bitcoin_pubkey();
        Address::p2wpkh(&pubkey, self.bitcoin.network).to_string()
    }

    pub fn get_database_with_name(&self, db_name: &str) -> String {
        let mut home = self.home.clone();
        home.push("data");
        home.push(db_name);
        home.display().to_string()
    }

}

pub fn home_dir(app_home: &str) -> PathBuf {
    dirs::home_dir().map(|path| path.join(app_home)).unwrap()
}
