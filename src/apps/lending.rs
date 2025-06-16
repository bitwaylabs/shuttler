

use cosmrs::Any;
use frost_adaptor_signature::VerifyingKey;
use side_proto::side::tss::{MsgCompleteDkg, MsgCompleteRefreshing, MsgSubmitSignatures, SigningType};

use crate::config::{VaultKeypair, APP_NAME_LENDING};
use crate::helper::encoding::{from_base64, hash, pubkey_to_identifier};
use crate::helper::mem_store;
use crate::helper::store::Store;
use crate::protocols::refresh::{ParticipantRefresher, RefreshAdaptor, RefreshInput};
use crate::protocols::sign::{SignAdaptor, StandardSigner};
use crate::protocols::dkg::{DKGAdaptor, DKG};

use crate::apps::{App, Context, FrostSignature, Input, SignMode, SubscribeMessage, Task};

use super::event::get_attribute_value;
use super::{SideEvent, TaskInput};

pub struct LendingApp {
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<SignerHandler>,
    pub refresher: ParticipantRefresher<RefreshHandler>,
}

impl LendingApp {
    pub fn new() -> Self {
        Self {
            keygen: DKG::new("lending_key_generator", KeygenHander{}),
            signer: StandardSigner::new("lending_signer", SignerHandler{}),
            refresher: ParticipantRefresher::new("lending_refresh", RefreshHandler{})
        }
    }
}

impl App for LendingApp {

    fn name(&self) -> String {
        APP_NAME_LENDING.to_string()
    }

    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>{
        self.signer.on_message(ctx, message)?;
        self.keygen.on_message(ctx, message)?;
        self.refresher.on_message(ctx, message)
    }
    fn subscribe_topics(&self) -> Vec<libp2p::gossipsub::IdentTopic> {
        vec![self.keygen.topic(), self.signer.topic(), self.refresher.topic()]
    }
    fn on_event(&self, ctx: &mut Context, event: &SideEvent) {
        self.signer.on_event(ctx, event);
        self.keygen.on_event(ctx, event);
        self.refresher.on_event(ctx, event);
    }
    fn execute(&self, ctx: &mut Context, tasks: Vec<Task>) -> anyhow::Result<()> {
        self.signer.execute(ctx, &tasks);
        Ok(())
    }
}
pub struct KeygenHander{}
impl DKGAdaptor for KeygenHander {
    fn new_task(&self, _ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("initiate_dkg.id") {

                    let live_peers = mem_store::alive_participants();

                    let mut tasks = vec![];
                    for (((id, ps), t), b) in events.get("initiate_dkg.id")?.iter()
                        .zip(events.get("initiate_dkg.participants")?)
                        .zip(events.get("initiate_dkg.threshold")?)
                        .zip(events.get("initiate_dkg.batch_size")?) {
                        
                            let mut participants = vec![];
                            let mut down_peers = vec![];
                            let mut names = vec![];
                            for p in ps.split(",") {
                                if let Ok(keybytes) = from_base64(p) {
                                    let identifier = pubkey_to_identifier(&keybytes);
                                    // not have enough participants
                                    let moniker = mem_store::get_participant_moniker(&identifier);
                                    if !live_peers.contains(&identifier) {
                                        down_peers.push(moniker.clone());
                                    } 
                                    names.push(moniker);
                                    
                                    participants.push(identifier);
                                }
                            };

                            tracing::debug!("Task {} has {} offline participants {:?} {:?}, threshold {}", id, down_peers.len(), down_peers, names, t);
                            if down_peers.len() > 0 {
                                continue;
                            }

                            if let Ok(threshold) = t.parse() {
                                if threshold as usize * 3 >= participants.len() * 2  {
                                    if let Ok(batch_size) = b.parse() {
                                        tasks.push(Task::new_dkg(format!("lending-dkg-{}", id), participants, threshold, batch_size));
                                    }
                                }
                            }
                        };
                    return Some(tasks);
                }
            },
            _ => {},
        }
        None
    }    
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage,frost_adaptor_signature::keys::PublicKeyPackage)>) {
        let mut pub_keys = vec![];
        keys.into_iter().for_each(|(priv_key, pub_key)| {
            
            let tweak = None;
            let rawkey = pub_key.verifying_key().serialize().unwrap();
            let hexkey = hex::encode(&rawkey[1..]);
            let keyshare = VaultKeypair {
                pub_key: pub_key.clone(),
                priv_key: priv_key.clone(),
                tweak,
            };
            ctx.keystore.save(&hexkey, &keyshare);
            pub_keys.push(hexkey);
        });

        // debug!("Oracle pubkey >>>: {:?}", pub_keys);

        // save dkg id and keys for refresh
        ctx.general_store.save(&format!("{}", task.id).as_str(), &pub_keys.join(","));
        
        // convert string array to bytes
        let id: u64 = task.id.replace("lending-dkg-", "").parse().unwrap();
        let mut message_keys = id.to_be_bytes()[..].to_vec();
        for key in pub_keys.iter() {
            let key_bytes = hex::decode(key).unwrap();
            message_keys.extend(key_bytes);
        };
        let message = hex::decode(hash(&message_keys)).unwrap();
        let signature = hex::encode(ctx.node_key.sign(&message, None));

        let cosm_msg = MsgCompleteDkg {
            id: id,
            sender: ctx.conf.relayer_bitcoin_address(),
            pub_keys: pub_keys,
            signature,
            consensus_pubkey: ctx.id_base64.clone()
        };

        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.send(any) {
            tracing::error!("{:?}", e)
        }

    }
}
pub struct SignerHandler{}
impl SignAdaptor for SignerHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent( events) => {
                if events.contains_key("initiate_signing.id") {
                    let mut tasks = vec![];
                    for ((((id, pub_key), sig_hashes), mode), option ) in events.get("initiate_signing.id")?.iter()
                        .zip(events.get("initiate_signing.pub_key")?)
                        .zip(events.get("initiate_signing.sig_hashes")?)
                        .zip(events.get("initiate_signing.type")?)
                        .zip(events.get("initiate_signing.option")?) {
    
                            let mut sign_mode = SignMode::Sign;                      
                            if mode.eq(&(SigningType::SchnorrWithCommitment as i32).to_string()) {
                                if let Some(nonce_keypair) = ctx.keystore.get(&option) { 
                                    sign_mode = SignMode::SignWithGroupcommitment(nonce_keypair.pub_key.verifying_key().clone())
                                }
                            } else if mode.eq(&(SigningType::SchnorrAdaptor as i32).to_string()) {
                                let hex_adaptor = hex::decode(&option).ok()?;
                                if let Ok(adaptor) = VerifyingKey::deserialize(&hex_adaptor) {
                                    // let mode = SignMode::SignWithAdaptorPoint(adaptor);    
                                    sign_mode = SignMode::SignWithAdaptorPoint(adaptor)
                                }
                            } else if mode.eq(&(SigningType::SchnorrWithTweak as i32).to_string()) {
                                sign_mode = SignMode::SignWithTweak
                            };
    
                            let participants = mem_store::count_task_participants(ctx, pub_key);
                            if participants.len() > 0 {
                                let mut sign_inputs = vec![];
                                sig_hashes.split(",").enumerate().for_each(|(index, sig)| {
                                    if let Ok(message) = from_base64(sig) {
                                            sign_inputs.insert(index, Input::new_with_message_mode(pub_key.clone(), message, participants.clone(), sign_mode.clone()));
                                        }
                                    }
                                );
                                if sign_inputs.len() > 0 {
                                    let task= Task::new_signing(format!("lending-{}", id), "" , sign_inputs);
                                    tasks.push(task);
                                }
                            }
                        };
                    return Some(tasks);
                }
            },
            SideEvent::TxEvent(events) => {
                let mut tasks = vec![];
                for e in events.iter().filter(|e| e.kind == "initiate_signing") {
                    let id = get_attribute_value(&e.attributes, "id")?;
                    let pub_key = get_attribute_value(&e.attributes, "pub_key")?;
                    let mode = get_attribute_value(&e.attributes, "type")?;
                    let sig_hashes = get_attribute_value(&e.attributes, "sig_hashes")?;
                    let option = get_attribute_value(&e.attributes, "option")?;

                    let mut sign_mode = SignMode::Sign;                      
                    if mode.eq(&(SigningType::SchnorrWithCommitment as i32).to_string()) {
                        if let Some(nonce_keypair) = ctx.keystore.get(&option) {    
                            sign_mode = SignMode::SignWithGroupcommitment(nonce_keypair.pub_key.verifying_key().clone())
                        }
                    } else if mode.eq(&(SigningType::SchnorrAdaptor as i32).to_string()) {
                        let hex_adaptor = hex::decode(&option).ok()?;
                        if let Ok(adaptor) = VerifyingKey::deserialize(&hex_adaptor) {
                            // let mode = SignMode::SignWithAdaptorPoint(adaptor);    
                            sign_mode = SignMode::SignWithAdaptorPoint(adaptor)
                        }
                    };

                    let participants = mem_store::count_task_participants(ctx, &pub_key);
                    if participants.len() > 0 {
                        let mut sign_inputs = vec![];
                        sig_hashes.split(",").enumerate().for_each(|(index, sig)| {
                            if let Ok(message) = from_base64(sig) {
                                    sign_inputs.insert(index, Input::new_with_message_mode(pub_key.clone(), message, participants.clone(), sign_mode.clone()));
                                }
                            }
                        );
                        if sign_inputs.len() > 0 {
                            let task= Task::new_signing(format!("lending-{}", id), "" , sign_inputs);
                            tasks.push(task);
                        }
                    }
                }
                return Some(tasks);
            }
        }
        
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task)-> anyhow::Result<()> {
        let mut signatures = vec![];

        if let TaskInput::SIGN(sign_inputs) = &task.input {
            for input in sign_inputs.iter() {
                if let Some(signature) = input.signature.clone() {
                    match signature {
                        FrostSignature::Standard(sig) => {
                            signatures.push(hex::encode(&sig.serialize()?));
                        }
                        FrostSignature::Adaptor(sig) => {
                            signatures.push(hex::encode(&sig.0.default_serialize()?));
                        }
                    }
                }
            }
            let cosm_msg = MsgSubmitSignatures {
                id: task.id.replace("lending-", "").parse()?,
                sender: ctx.conf.relayer_bitcoin_address(),
                signatures ,
            };
            let any = Any::from_msg(&cosm_msg)?;
            if let Err(e) = ctx.tx_sender.send(any) {
                tracing::error!("{:?}", e)
            }
        }
        
        Ok(())
    }
}

pub struct RefreshHandler;
impl RefreshAdaptor for RefreshHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent( events) => {
                if events.contains_key("initiate_refreshing.id") {
                    println!("Events: {:?}", events);
                    let mut tasks = vec![];
                    let live_peers = mem_store::alive_participants();
                    for ((id, dkg_id), removed) in events.get("initiate_refreshing.id")?.iter()
                        .zip(events.get("initiate_refreshing.dkg_id")?)
                        .zip(events.get("initiate_refreshing.removed_participants")?){

                            let dkg_keys = match ctx.general_store.get(&format!("lending-dkg-{}", dkg_id).as_str()) {
                                Some(k) => k.split(',').map(|t| t.to_owned()).collect::<Vec<_>>(),
                                None => continue,
                            };

                            let removed_ids = removed.split(",").map(|k| pubkey_to_identifier(&from_base64(k).unwrap())).collect::<Vec<_>>();
                            if removed_ids.contains(&ctx.identifier) {
                                dkg_keys.iter().for_each(|k| {ctx.keystore.remove(k);} );
                                continue;
                            }

                            let first_key = match dkg_keys.get(0) {
                                Some(k) => k,
                                None => continue,
                            };

                            let first_key_pair = match ctx.keystore.get(&first_key.to_string()) {
                                Some(k) => k,
                                None => continue,
                            };

                            let participants = first_key_pair.pub_key.verifying_shares()
                                .keys().filter(|i| !removed_ids.contains(i) ).map(|i| i.clone()).collect::<Vec<_>>();

                            if participants.iter().any(|i| !live_peers.contains(&i)) {
                                continue;
                            }

                            let task_id = format!("lending-refresh-{}", id);
                            let input = RefreshInput{
                                id: task_id.clone(),
                                keys: dkg_keys,
                                threshold: first_key_pair.priv_key.min_signers().clone() - 1,
                                remove_participants: removed_ids,
                                new_participants: participants,
                            };
                            tasks.push(Task::new_with_input(task_id, TaskInput::REFRESH(input), "".to_owned()));
                        };
                    return Some(tasks);
                }
            },
            SideEvent::TxEvent(_events) => {
            }
        }
        None
    }

    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage, frost_adaptor_signature::keys::PublicKeyPackage)>) {

        if let Ok(id) = task.id.replace("lending-refresh-", "").parse::<u64>() {
            let mut message_keys = id.to_be_bytes()[..].to_vec();
            for (priv_key, key) in keys.iter() {
                // let key_bytes = hex::decode(key).unwrap();
                let key_bytes = key.verifying_key().serialize().unwrap();
                
                let tweak = None;
                let hexkey = hex::encode(&key_bytes[1..]);
                let keyshare = VaultKeypair {
                    pub_key: key.clone(),
                    priv_key: priv_key.clone(),
                    tweak,
                };
                ctx.keystore.save(&hexkey, &keyshare);
                message_keys.extend(&key_bytes[1..]);
            };
            let message = hex::decode(hash(&message_keys)).unwrap();
            let signature = hex::encode(ctx.node_key.sign(&message, None));
    
            let msg = MsgCompleteRefreshing {
                id,
                sender: ctx.conf.relayer_bitcoin_address(),
                consensus_pubkey: ctx.id_base64.clone(),
                signature,
            };
            let any = Any::from_msg(&msg).unwrap();
            if let Err(e) = ctx.tx_sender.send(any) {
                tracing::error!("{:?}", e)
            }
        }
        
    }
}
