use std::{collections::BTreeMap, fs};

use cosmrs::Any;
use serde::{Deserialize, Serialize};
use side_proto::side::btcbridge::MsgCompleteDkg;
use tendermint::abci::{Event, EventAttribute};

use crate::{apps::SideEvent, mock::{fullpath, generate_mock_psbt}};

use super::{EventQueue, MockEnv, SINGING_FILE_NAME, VAULT_FILE_NAME};

#[derive(Serialize, Deserialize)]
pub struct KeygenParameter {
    pub id: u64,
    pub participants: Vec<String>,
    pub threshold: u32,
}

#[derive(Serialize, Deserialize)]
pub struct BridgeSigningRequest { 
    pub address: String, 
    pub sequence: u64, 
    pub txid: String, 
    pub psbt: String, 
    pub status: i32, 
}
pub fn bridge_task_queue() -> EventQueue {
    // height, event
    let mut queue: EventQueue = EventQueue::new();
    queue.insert(3, create_vault_event);
    queue.insert(5, create_transaction_event);
    // queue.insert(7, create_transaction_event);
    // queue.insert(8, exit_queue);
    queue
}

pub fn create_vault_event(env: MockEnv) -> SideEvent {
    let mut creation = BTreeMap::new();
    creation.insert("create_bridge_vault.id".to_owned(), vec!["1".to_owned()]);
    creation.insert("create_bridge_vault.participants".to_owned(), vec![env.participants.join(",")]);
    creation.insert("create_bridge_vault.tweaks".to_owned(), vec!["1".to_owned()]);
    creation.insert("create_bridge_vault.threshold".to_owned(), vec![(env.participants.len() * 2 / 3).to_string()]);
    SideEvent::BlockEvent(creation)
}

pub fn create_transaction_event(env: MockEnv) -> SideEvent {

    let mut events = vec![];
    if let Ok(txs) = fs::read_to_string(fullpath(&env.home, SINGING_FILE_NAME)) {
        // generate psbt
        txs.split(",").for_each(|t| {
            let tt = t.split("##").collect::<Vec<_>>();
            if tt.len() == 2 {
                events.push( Event::new("bridge_transaction".to_owned(), vec![
                    EventAttribute::from(("txid", tt[0], false)),
                    EventAttribute::from(("psbt", tt[1], false)),
                ]));
            }
        });
    }
    
    SideEvent::TxEvent(events)
}

pub fn handle_bridge_dkg_submission(home: &str, tx_num: u32, m : &Any) {
    if let Ok(msg) = m.to_msg::<MsgCompleteDkg>() {

        println!("received vault: {:?}", msg.vaults);
        // let num = rand::random::<u32>() % 5 + 1;
        let path_addr = fullpath(home, VAULT_FILE_NAME);
        if let Ok(addresses) = fs::read_to_string(&path_addr) {
            if msg.vaults.iter().any(|v| addresses.contains(v)) {
                return
            }
        }
        if fs::write(path_addr, msg.vaults.join(",").as_bytes()).is_ok() {
            println!("saved vault: {:?}", msg.vaults)
        }

        let mut content = vec![];
        for addr in msg.vaults {
            let (txid, psbt) = generate_mock_psbt(&addr, Some(tx_num));
            content.push(format!("{}##{}", txid, psbt));
        }
        if fs::write(fullpath(home, SINGING_FILE_NAME), content.join(",").as_bytes()).is_ok() {
            println!("generated txs for signing");
        }
    }
}