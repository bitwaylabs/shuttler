use std::{collections::BTreeMap, fs};

use cosmrs::Any;
use side_proto::{prost::Message, 
    side::{
        dlc::{DlcOracle, DlcOracleStatus}, 
        tss::{MsgCompleteDkg, MsgSubmitSignatures}},
    };
use tendermint::block::Height;

use crate::apps::SideEvent;

use super::{fullpath, EventQueue, MockEnv};

const ORACLE_DKG_FILE_NAME: &str = "oracle.data";
// const EVENT_FILE_NAME: &str = "event.prost";

pub fn lending_task_queue() -> EventQueue {
    // height, event
    let mut queue: EventQueue = EventQueue::new();
    queue.insert(3, create_oracle_event);
    queue.insert(5, create_signing_event);
    queue.insert(7, create_refresh_event);
    queue.insert(9, create_signing_event);
    queue
}

pub fn handle_lending_dkg_submission(home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgCompleteDkg>() {
        let key = fullpath(home, &msg.pub_keys[0]);
        println!("Received: {:?} from {}", msg.pub_keys, msg.sender);
        
        if fs::exists(&key).unwrap_or(false) {
            return
        }
        fs::create_dir_all(fullpath(home, key)).unwrap();

        let mut o = DlcOracle::default();
        o.id = msg.id;
        o.pubkey = msg.pub_keys[0].clone();
        o.status = DlcOracleStatus::OracleStatusEnable as i32;

        fs::write(fullpath(home, ORACLE_DKG_FILE_NAME ), o.encode_to_vec()).unwrap();
    }
}

pub fn handle_signature_submission(_home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgSubmitSignatures>() {
        println!("Received: {:?}", msg);
    }
}

pub fn create_oracle_event(env: MockEnv, height: Height) -> SideEvent {
    let mut creation = BTreeMap::new();
    let n = env.participants.len();
    creation.insert("initiate_dkg.id".to_owned(), vec![height.value().to_string()]);
    creation.insert("initiate_dkg.participants".to_owned(), vec![env.participants[0..n].join(",")]);
    creation.insert("initiate_dkg.threshold".to_owned(), vec![(n - 1).to_string()]);
    creation.insert("initiate_dkg.batch_size".to_owned(), vec!["2".to_owned()]);

    SideEvent::BlockEvent(creation)
}

pub fn create_signing_event(env: MockEnv, height: Height) -> SideEvent {
    if let Ok(bytes) = fs::read(fullpath(&env.home, ORACLE_DKG_FILE_NAME)) {
        let o = DlcOracle::decode(bytes.as_slice()).unwrap();

        let mut creation = BTreeMap::new();
        creation.insert("initiate_signing.id".to_owned(), vec![height.value().to_string()]);
        creation.insert("initiate_signing.type".to_owned(), vec!["0".to_owned()]);
        creation.insert("initiate_signing.sig_hashes".to_owned(), vec![o.pubkey.to_string()]);
        creation.insert("initiate_signing.pub_key".to_owned(), vec![o.pubkey]);
        creation.insert("initiate_signing.option".to_owned(), vec!["".to_owned()]);
    
        SideEvent::BlockEvent(creation)
    } else {
        SideEvent::BlockEvent(BTreeMap::new()) // empty event if file not found
    }
}

pub fn create_refresh_event(env: MockEnv, height: Height) -> SideEvent {
    if let Ok(bytes) = fs::read(fullpath(&env.home, ORACLE_DKG_FILE_NAME)) {
        let o = DlcOracle::decode(bytes.as_slice()).unwrap();

        let mut creation = BTreeMap::new();
        creation.insert("initiate_refreshing.id".to_owned(), vec![height.value().to_string()]);
        creation.insert("initiate_refreshing.dkg_id".to_owned(), vec![o.id.to_string()]);
        creation.insert("initiate_refreshing.removed_participants".to_owned(), vec![env.participants.iter().nth(3).unwrap().to_string()]); // remove the first one
        creation.insert("initiate_refreshing.new_participants".to_owned(), vec![]); // add the last one

        SideEvent::BlockEvent(creation)
    } else {
        SideEvent::BlockEvent(BTreeMap::new()) // empty event if file not found
    }
}