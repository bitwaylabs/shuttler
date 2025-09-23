use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use ed25519_compact::{x25519, SecretKey};
use tendermint_config::PrivValidatorKey;

use crate::{
    apps::{
        Round1SecretStore, Round1Store, Round2SecretStore, Round2Store, Task, TaskInput
    }, 
    config::{Config, VaultKeypair}, helper::{cipher::decrypt, encoding::pubkey_to_identifier, store::{DefaultStore, Store}},
};

use frost_adaptor_signature as frost;

pub struct DataStore {
    pub keystore: DefaultStore<String, VaultKeypair>,
    pub task_store: Arc<DefaultStore<String, Task>>,
    // pub nonce_store: SignerNonceStore,
    // pub commitment_store: CommitmentStore,
    // pub signature_store: SignatureShareStore,
    // pub general_store: DefaultStore<&'static str, String>,

    // dkg stores
    pub db_round1: Round1Store,
    pub db_round2: Round2Store,
    pub sec_round1: Round1SecretStore,
    pub sec_round2: Round2SecretStore,
}

impl DataStore {
    fn new(data: String) -> Self {
        Self{
            keystore: DefaultStore::new(format!("{}/data/keypairs", data)),
            task_store: Arc::new(DefaultStore::new(format!("{}/data/tasks", data))),
            // nonce_store: SignerNonceStore::new(format!("{}/nonces", data)),
            // commitment_store: CommitmentStore::new(format!("{}/commitments", data)),
            // signature_store: SignatureShareStore::new(format!("{}/signature_shares", data)),
            // general_store: DefaultStore::new(format!("{}/general", data)),

            db_round1: Round1Store::new(format!("{}/data/round1", data)),
            db_round2: Round2Store::new(format!("{}/data/round2", data)),
            sec_round1: Round1SecretStore::new(format!("{}/data/sec_round1", data)),
            sec_round2: Round2SecretStore::new(format!("{}/data/sec_round2", data)),
        }
    }
}

pub fn load_validator_key(priv_validator_key_path: String) -> PrivValidatorKey {
    
    let priv_key_path = PathBuf::from(priv_validator_key_path.clone());
    let text = fs::read_to_string(priv_key_path.clone()).expect("priv_validator_key.json does not exists!");
    let prv_key = serde_json::from_str::<PrivValidatorKey>(text.as_str()).expect("Failed to parse priv_validator_key.json");

    prv_key    
}

pub async fn execute(data: String) {

    let contents = fs::read_to_string(format!("{}/config.toml", data) ).expect("Invalid Home Directory");
    let config: Config = toml::from_str(&contents).expect("Failed to parse config file");
    let priv_validator_key = load_validator_key(config.priv_validator_key_path);

    let mut b = priv_validator_key
        .priv_key
        .ed25519_signing_key()
        .unwrap()
        .as_bytes()
        .to_vec();
    b.extend(priv_validator_key.pub_key.to_bytes());

    let node_key = SecretKey::new(b.as_slice().try_into().unwrap());
    let identifier = pubkey_to_identifier(node_key.public_key().as_slice());

    let data_store = DataStore::new(data);

    for i in data_store.sec_round1.list() {
        println!("recover: {:?}", String::from_utf8_lossy(&i.0));
        let task_id = &String::from_utf8_lossy(&i.0).to_string();

        let task = match data_store.task_store.get(&task_id) {
            Some(t) => t,
            None => continue,
        };

        let dkg_input = match &task.input {
            TaskInput::DKG(i) => i,
            _ => continue
        };
        // initialize a batch of empty BTreeMap.
        let mut batch = (0..dkg_input.batch_size).map(|_i| BTreeMap::new() ).collect::<Vec<_>>();
        
        let received = match data_store.db_round2.get(&task_id) {
            Some(d) => d,
            None => continue,
        };
        // let mut round2_packages = BTreeMap::new();
        received.iter().filter(|(k, _)| *k != &identifier ).for_each(|(sender, packet)| {
            
            let bz = sender.serialize();
            let source = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
            let share_key = source.dh(&x25519::SecretKey::from_ed25519(&node_key).unwrap()).unwrap();

            for (round2_packages, p) in batch.iter_mut().zip(packet.iter()) {
                let p = decrypt(p, share_key.as_slice().try_into().unwrap());
                let received_round2_package = frost::keys::dkg::round2::Package::deserialize(&p).unwrap();
                round2_packages.insert(sender.clone(), received_round2_package);
            }

        });

        // compute the threshold key
        let round2_secret_package = match data_store.sec_round2.get(task_id) {
            Some(secret_package) => secret_package,
            None => {
                continue;
            }
        };

        let mut round1_packages = match data_store.db_round1.get(task_id) {
            Some(d) => d,
            None => continue,
        };

        // frost does not need its own package to compute the threshold key
        round1_packages.remove(&identifier);

        // let mut keys = vec![];
        batch.iter().zip(round2_secret_package).enumerate().for_each(|(i, (round2_packages,round2_secret_package ))| {
            // extract the ith round1 package
            let mut ith_round1_packages = BTreeMap::new();
            for (k, v) in round1_packages.iter_mut() {
                if v.len() >= i {
                    ith_round1_packages.insert(k.clone(), v[i].clone());
                }
            } 
            match frost::keys::dkg::part3(&round2_secret_package, &ith_round1_packages, &round2_packages ) {
                Ok((priv_key, pub_key)) => {
                    println!("recovered: {:?}", pub_key);
                    // keys.push((priv_key, pub_key));

                    let rawkey = pub_key.verifying_key().serialize().unwrap();
                    let hexkey = hex::encode(&rawkey[1..]);
                    let keyshare = VaultKeypair {
                        pub_key: pub_key.clone(),
                        priv_key: priv_key.clone(),
                        tweak: None,
                    };
                    data_store.keystore.save(&hexkey, &keyshare);
                },
                Err(e) => {
                    println!("dkg failure: {}", e)
                }
            }; 
        });

    }

}