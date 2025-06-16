/// This is the store module. It is used to store the secret packets for DKG round 1 and 2.
/// The secret packets are stored in memory for security reasons. 
/// The secret packets should not shared with other nodes in the network.
/// If the node restarts during the DKG process, the secret packets will be lost and the DKG process will be failed.

use std::collections::BTreeMap;

use frost_adaptor_signature::{keys::dkg, Identifier};
use std::sync::Mutex;
use lazy_static::lazy_static;

use crate::apps::Context;
use crate::config::BLOCK_TOLERENCE;
use super::store::Store;
use super::{gossip::HeartBeatMessage, now};

lazy_static! {
    static ref DkgRound1SecretPacket: Mutex<BTreeMap<String, Vec<dkg::round1::SecretPackage>>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound2SecretPacket: Mutex<BTreeMap<String, Vec<dkg::round2::SecretPackage>>> = {
        Mutex::new(BTreeMap::new())
    };
    pub static ref AliveTable: Mutex<BTreeMap<Identifier, u64>> = {
        Mutex::new(BTreeMap::new())
    };
    pub static ref TrustedPeers: Mutex<Vec<Identifier>> = {
        Mutex::new(Vec::new())
    };
    pub static ref TaskParticipants: Mutex<BTreeMap<String,Vec<Identifier>>> = {
        Mutex::new(BTreeMap::new())
    };
    pub static ref Monikers: Mutex<BTreeMap<Identifier, String>> = {
        Mutex::new(BTreeMap::new())
    };
}

pub fn alive_participants() -> Vec<Identifier> {
    let table= AliveTable.lock().unwrap();
        // tracing::debug!("alive: {:?}", table);
        table.keys()
            .map(|k| k.clone())
            .collect::<Vec<_>>()
}

pub fn alive_participants_monikers() -> Vec<String> {
    let table= AliveTable.lock().unwrap();
    let monikers =  Monikers.lock().unwrap();
        // tracing::debug!("alive: {:?}", table);
        table.keys()
            .map(|k| match monikers.get(k) {
                Some(m) => m.clone(),
                None => crate::helper::encoding::to_base64(&k.serialize()),
            })
            .collect::<Vec<_>>()
}

pub fn offline_participants_monikers() -> Vec<String> {
    let table= AliveTable.lock().unwrap();
    let monikers =  Monikers.lock().unwrap();
        // tracing::debug!("alive: {:?}", table);
    monikers.iter()
        .filter(|(id, _)| !table.contains_key(id))
        .map(|(_, m)| m.clone())
        .collect::<Vec<_>>()
}

pub fn get_participant_moniker(id: &Identifier) -> String {
    let monikers =  Monikers.lock().unwrap();
        // tracing::debug!("alive: {:?}", table);
    monikers.get(id)
        .cloned()
        .unwrap_or_else(|| crate::helper::encoding::to_base64(&id.serialize()))
}

pub fn update_alive_table(self_identifier: &Identifier, alive: HeartBeatMessage) {

    // tracing::debug!("{:?} {}, {} ", alive.payload.identifier, alive.payload.block_height, if alive.payload.last_seen > now() {alive.payload.last_seen - now()} else {0} );
    if alive.payload.last_seen < now() { return }

    let mut table= AliveTable.lock().unwrap();

    if let Some(t) = table.get(&self_identifier) {
        if alive.payload.block_height.abs_diff(t.clone()) > BLOCK_TOLERENCE { return }
    }

    table.insert(alive.payload.identifier, alive.payload.block_height);
    table.retain(|_, v| v.abs_diff(alive.payload.block_height) <= BLOCK_TOLERENCE);

}

pub fn count_task_participants(ctx: &Context, key: &String) -> Vec<Identifier> {
    if let Some(vkp) = ctx.keystore.get(key) {
        let table= AliveTable.lock().unwrap();
        // tracing::debug!("alive: {:?}", table);
        table.keys()
            .filter(|alive| {vkp.pub_key.verifying_shares().contains_key(alive)})
            .map(|k| k.clone())
            .collect::<Vec<_>>()
    } else {
        vec![]
    }
}

pub fn is_peer_alive(identifier: &Identifier) -> bool {
    let table= AliveTable.lock().unwrap();
   table.contains_key(identifier)
}

pub fn is_peer_trusted_peer( ctx: &Context, identifier: &Identifier) -> bool {
    let mut table= TrustedPeers.lock().unwrap();
    if table.contains(identifier) {
        true
    } else if ctx.keystore.list().iter().any(|a| a.pub_key.verifying_shares().contains_key(identifier)) {
        table.push(identifier.clone());
        true
    } else {
        false
    }
}

pub fn add_moniker(identifier: &Identifier, moniker: String) {
    let mut map = Monikers.lock().unwrap();
    map.insert(identifier.clone(), moniker);
}

pub fn get_dkg_round1_secret_packet(task_id: &str) -> Option<Vec<dkg::round1::SecretPackage>> {
    let map = DkgRound1SecretPacket.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round1_secret_packet(task_id: &str, secret_packet: Vec<dkg::round1::SecretPackage>) {
    let mut map = DkgRound1SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn remove_dkg_round1_secret_packet(task_id: &str) {
    let mut map = DkgRound1SecretPacket.lock().unwrap();
    map.remove(task_id);
}

pub fn get_dkg_round2_secret_packet(task_id: &str) -> Option<Vec<dkg::round2::SecretPackage>> {
    let map = DkgRound2SecretPacket.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round2_secret_packet(task_id: &str, secret_packet: Vec<dkg::round2::SecretPackage>) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn remove_dkg_round2_secret_packet(task_id: &str) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.remove(task_id);
}
