
use crate::{config::{Config, VaultKeypair}, helper::store::{DefaultStore, Store}};


pub async fn execute(home: &str, store_key: String, pubkey: String) {

    let conf = Config::from_file(home).unwrap();
    let keystore: DefaultStore<String, VaultKeypair> = DefaultStore::new(conf.get_database_with_name("keypairs"));

    println!("home: {:?}", home,);
    let keypair = keystore.get(&store_key).expect("key not found");

    let local_pubkey = keypair.pub_key.verifying_key().serialize().expect("Serialize failure");

    println!("local pubkey: {:?} =? {:?}", hex::encode(local_pubkey), pubkey);

    println!("public verify share {:?}",  keypair.pub_key.verifying_shares());
    
}