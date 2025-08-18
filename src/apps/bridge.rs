
use cosmrs::Any;
use libp2p::gossipsub::IdentTopic;
use tracing::{error, info};
use bitcoin::{Network, TapNodeHash, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client};
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};

use bitway_proto::bitway::btcbridge::{MsgCompleteDkg, MsgCompleteRefreshing, MsgSubmitSignatures};

use crate::apps::{App, Context, Input, SignMode, Status, SubscribeMessage, Task };
use crate::config::{Config, VaultKeypair, APP_NAME_BRIDGE, BRIDGE_KEY_REFRESH};
use crate::helper::bitcoin::get_group_address_by_tweak;
use crate::helper::encoding::{from_base64, hash, pubkey_to_identifier};

use crate::helper::mem_store;
use crate::helper::store::Store;
use crate::protocols::dkg::{DKGAdaptor, DKG};
use crate::protocols::refresh::{ParticipantRefresher, RefreshAdaptor, RefreshInput};
use crate::protocols::sign::{SignAdaptor, StandardSigner};

use super::event::get_attribute_value;
use super::{SideEvent, TaskInput};

// #[derive(Debug)]
pub struct BridgeApp {
    pub bitcoin_client: Client,
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<SignatureHandler>,
    pub refresh: ParticipantRefresher<RefreshHandler>
}

pub static TASK_PREFIX_KEYGEN: &str = "create-vault-";
pub static TASK_PREFIX_REFRESH: &str = "bridge-refresh-";


impl BridgeApp {
    pub fn new(conf: Config) -> Self {
        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc,
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone()),
        )
        .expect("Could not initial bitcoin RPC client");

        Self {
            bitcoin_client,
            keygen: DKG::new("bridge_dkg", KeygenHander{}),
            signer: StandardSigner::new("bridge_signing", SignatureHandler{}),
            refresh: ParticipantRefresher::new("bridge_refresh", RefreshHandler{})
        }
    }  
}

impl App for BridgeApp {
    fn name(&self) -> String {
        APP_NAME_BRIDGE.to_string()
    }
    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        // debug!("Received {:?}", message);
        self.keygen.on_message(ctx, message)?;
        self.refresh.on_message(ctx, message)?;
        self.signer.on_message(ctx, message)
    }
    
    fn subscribe_topics(&self) -> Vec<IdentTopic> {
        vec![self.keygen.topic(), self.signer.topic(), self.refresh.topic()]
    }
    fn on_event(&self, ctx: &mut Context, event: &SideEvent) {
        self.keygen.on_event(ctx, event);
        self.signer.on_event(ctx, event);
        self.refresh.on_event(ctx, event);
    }
    fn execute(&self, ctx: &mut Context, tasks: Vec<Task>) -> anyhow::Result<()> {
        self.signer.execute(ctx, &tasks);
        Ok(())
    }
}

pub struct KeygenHander{}
impl DKGAdaptor for KeygenHander {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("initiate_dkg_bridge.id") {
                    // println!("Events: {:?}", events);
                    let live_peers = mem_store::alive_participants();
                    let mut tasks = vec![];
                    for (((id, ps), tks ), t)in events.get("initiate_dkg_bridge.id")?.iter()
                        .zip(events.get("initiate_dkg_bridge.participants")?)
                        .zip(events.get("initiate_dkg_bridge.batch_size")?)
                        .zip(events.get("initiate_dkg_bridge.threshold")?) {
                        
                            let mut participants = vec![];
                            for p in ps.split(",") {
                                if let Ok(key_bytes) = from_base64(p) {
                                    let identifier = pubkey_to_identifier(&key_bytes);
                                    if !live_peers.contains(&identifier) {
                                        break;
                                    }
                                    participants.push(identifier);
                                }
                            };
                            if let Ok(size) = tks.parse::<i32>() {
                                let tweaks = (0..size).collect();
                                if let Ok(threshold) = t.parse() {
                                    if threshold as usize * 2 >= participants.len() && participants.len() == ps.len() {
                                        tasks.push(Task::new_dkg_with_tweak(format!("{}{}", TASK_PREFIX_KEYGEN, id), participants, threshold,  tweaks));
                                    }
                                }

                            };
                        };
                    return Some(tasks);
                }
            },
            _ => {},
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage,frost_adaptor_signature::keys::PublicKeyPackage)>) {
        let (priv_key, pub_key) = keys.into_iter().next().unwrap();
        
        let dkg_input = match &task.input {
            TaskInput::DKG(i) => i,
            _ => return
        };
        
        let vaults = generate_vault_addresses(ctx, pub_key.clone(), priv_key.clone(), &dkg_input.tweaks, ctx.conf.bitcoin.network);

        ctx.general_store.save(&format!("{}", task.id).as_str(), &vaults.join(","));
        let id: u64 = task.id.replace(TASK_PREFIX_KEYGEN, "").parse().unwrap();
        let mut sig_msg = id.to_be_bytes().to_vec();

        for v in &vaults {
            sig_msg.extend(v.as_bytes())
        }

        let message = hex::decode(hash(&sig_msg)).unwrap();
        let signature = hex::encode(ctx.node_key.sign(message, None));
        let cosm_msg = MsgCompleteDkg {
            id,
            sender: ctx.conf.relayer_bitcoin_address(),
            vaults,
            consensus_pubkey: ctx.id_base64.clone(),
            signature,
        };
        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.send(any) {
            error!("{:?}", e)
        }
    }
}

fn generate_tweak(pubkey: PublicKeyPackage, index: &i32) -> Option<TapNodeHash> {
    let key_bytes = match pubkey.verifying_key().serialize() {
        Ok(b) => b,
        Err(_) => return None,
    };
    let x_only_pubkey = XOnlyPublicKey::from_slice(&key_bytes[1..]).unwrap();

    let mut script = bitcoin::ScriptBuf::new();
    script.push_slice(x_only_pubkey.serialize());
    script.push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
    script.push_slice(index.to_be_bytes() );

    Some(TapNodeHash::from_script(
        script.as_script(),
        bitcoin::taproot::LeafVersion::TapScript,
    ))
}

pub fn generate_vault_addresses(
    ctx: &mut Context,
    pub_key: PublicKeyPackage,
    priv_key: KeyPackage,
    tweaks: &Vec<i32>,
    network: Network,
) -> Vec<String> {
    let mut addrs = vec![];
    for t in tweaks {
        let tweak = generate_tweak(pub_key.clone(), t);
        let address_with_tweak = get_group_address_by_tweak( &pub_key.verifying_key(), tweak.clone(), network );

        ctx.keystore.save(&address_with_tweak.to_string(), &VaultKeypair { priv_key: priv_key.clone(), pub_key: pub_key.clone(), tweak });

        addrs.push(address_with_tweak.to_string());
    }

    info!("Generated vault addresses: {:?}", addrs);
    addrs
}

pub struct SignatureHandler{}
impl SignAdaptor for SignatureHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("initiate_signing_bridge.id") {
                    println!("Bridge Signing Event: {:?}", events);
                    let mut tasks = vec![];
                    for ((id, s), h) in events.get("initiate_signing_bridge.id")?.iter()
                        .zip(events.get("initiate_signing_bridge.signers")?)
                        .zip(events.get("initiate_signing_bridge.sig_hashes")?) {
    
                            let mut inputs = vec![];
                            s.split(",").zip(h.split(",")).for_each(|(signer, sig_hash)| {
                                if let Some(sign_key) = ctx.keystore.get(&signer.to_string()) {
                                    let participants = mem_store::count_task_participants(ctx, &signer.to_string());
                                    if participants.len() >= sign_key.priv_key.min_signers().clone() as usize {
                                        let input = Input::new_with_message_mode(signer.to_string(), from_base64(sig_hash).unwrap(), participants, SignMode::SignWithTweak);
                                        inputs.push(input);
                                    }
                                }
                            });
                            if inputs.len() > 0 {
                                tasks.push( Task::new_signing(id.to_string(), "", inputs));
                            }
                        };
                    return Some(tasks);
                }
            },
            SideEvent::TxEvent(events) => {
                let mut tasks = vec![];
                for e in events.iter().filter(|e| e.kind == "initiate_signing_bridge") {
                    let id = get_attribute_value(&e.attributes, "id")?;
                    let s = get_attribute_value(&e.attributes, "signers")?;
                    let h = get_attribute_value(&e.attributes, "sig_hashes")?;

                    let mut inputs = vec![];
                    s.split(",").zip(h.split(",")).for_each(|(signer, sig_hash)| {
                        if let Some(sign_key) = ctx.keystore.get(&signer.to_string()) {
                            let participants = mem_store::count_task_participants(ctx, &signer.to_string());
                            if participants.len() >= sign_key.priv_key.min_signers().clone() as usize {
                                let input = Input::new_with_message_mode(signer.to_string(), from_base64(sig_hash).unwrap(), participants, SignMode::SignWithTweak);
                                inputs.push(input);
                            }
                        }
                    });
                    if inputs.len() > 0 {
                        tasks.push( Task::new_signing(id.to_string(), "", inputs));
                    }
                }
                return Some(tasks);
            },

        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()> {

        if task.submitted {
            return anyhow::Ok(());
        }

        let sign_inputs = match &task.input {
            TaskInput::SIGN(i) => i,
            _ => return anyhow::Ok(()), 
        };

        let signatures = sign_inputs.iter()
            .map(|input| hex::encode(&input.signature.as_ref().unwrap().inner().serialize().unwrap()))
            .collect::<Vec<_>>();
        // submit signed psbt to side chain
        let msg = MsgSubmitSignatures {
            sender: ctx.conf.relayer_bitcoin_address(),
            txid: task.id.to_string(),
            signatures: signatures,
        };

        let any = Any::from_msg(&msg)?;
        ctx.tx_sender.send(any)?;

        task.submitted = true;
        // task.memo = to_base64(&psbt_bytes);
        task.status = Status::Complete;
        ctx.task_store.save(&task.id, &task);

        anyhow::Ok(())
    }
}

pub struct RefreshHandler;
impl RefreshAdaptor for RefreshHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent( events) => {
                if events.contains_key("initiate_refreshing_bridge.id") {
                    let live_peers = mem_store::alive_participants();
                    let mut tasks = vec![];
                    for ((id, dkg_id), removed) in events.get("initiate_refreshing_bridge.id")?.iter()
                        .zip(events.get("initiate_refreshing_bridge.dkg_id")?)
                        .zip(events.get("initiate_refreshing_bridge.removed_participants")?){

                            let vault_addrs = match ctx.general_store.get(&format!("{}{}", TASK_PREFIX_KEYGEN, dkg_id).as_str()) {
                                Some(k) => k.split(',').map(|t| t.to_owned()).collect::<Vec<_>>(),
                                None => continue,
                            };

                            let removed_ids = removed.split(",").map(|k| pubkey_to_identifier(&from_base64(k).unwrap())).collect::<Vec<_>>();
                            if removed_ids.contains(&ctx.identifier) {
                                vault_addrs.iter().for_each(|k| {ctx.keystore.remove(k);} );
                                continue;
                            }

                            let first_key = match vault_addrs.get(0) {
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

                            let task_id = format!("{}{}", TASK_PREFIX_REFRESH, id);
                            let input = RefreshInput{
                                id: task_id.clone(),
                                keys: vec![first_key.clone()], // only refresh the first one for all tweaked vault addresses
                                threshold: first_key_pair.priv_key.min_signers().clone(),
                                remove_participants: removed_ids,
                                new_participants: participants,
                            };
                            tasks.push(Task::new_with_input(task_id, TaskInput::REFRESH(input), vault_addrs.join(",")));
                        };
                    return Some(tasks);
                } else if events.contains_key("refreshing_completed_bridge.id") {
                    for (id, dkg_id) in events.get("refreshing_completed_bridge.id")?.iter()
                        .zip(events.get("refreshing_completed_bridge.dkg_id")?) {

                            let store_id = format!("{}-{}", BRIDGE_KEY_REFRESH, id);
                            let backup = match ctx.general_store.get(&store_id.as_str()) {
                                Some(r) => r,
                                None => return None,
                            };

                            let keys = match serde_json::from_str::<Vec<(frost_adaptor_signature::keys::KeyPackage, frost_adaptor_signature::keys::PublicKeyPackage)>>(&backup) {
                                Ok(k) => k,
                                Err(e) => {
                                    error!("unable to load refreshed keypairs: {}", e);
                                    return None
                                },
                            };

                            if let Some(new_key) = keys.iter().next() {
                                
                                let vault_addrs = match ctx.general_store.get(&format!("{}{}", TASK_PREFIX_KEYGEN, dkg_id).as_str()) {
                                    Some(k) => k.split(',').map(|t| t.to_owned()).collect::<Vec<_>>(),
                                    None => {
                                        error!("have not found original key for updated: {}", dkg_id);
                                        return None;
                                    },
                                };

                                vault_addrs.iter().for_each(|k| {
                                    if let Some(vault) = ctx.keystore.get(k).as_mut() {
                                        vault.priv_key = new_key.0.clone();
                                        vault.pub_key = new_key.1.clone();
                                        ctx.keystore.save(k, &vault);
                                    };
                                } );
                            };

                            ctx.general_store.remove(&store_id.as_str());
                            ctx.clean_dkg_cache(id);

                        }
                }
            },
            SideEvent::TxEvent(_events) => {
            }
        }
        None
    }

    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage, frost_adaptor_signature::keys::PublicKeyPackage)>) {

        if let Ok(id) = task.id.replace(TASK_PREFIX_REFRESH, "").parse::<u64>() {

            if keys.len() == 0 {
                error!("have not received any refreshed key for task: {}", id);
                return;
            }

            // cache refreshed key for future replacement
            ctx.general_store.save(&format!("{}-{}", BRIDGE_KEY_REFRESH, task.id).as_str(), &serde_json::to_string(&keys).unwrap());
            
            let message_keys = id.to_be_bytes()[..].to_vec();

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