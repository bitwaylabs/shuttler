

use core::fmt;
use std::{collections::BTreeMap, fmt::Debug};
use ed25519_compact::x25519;
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};
use libp2p::gossipsub::IdentTopic;
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

use frost_adaptor_signature as frost;
use frost::{Identifier, keys::dkg::round1};

use crate::apps::{Context, SideEvent, Status, SubscribeMessage, Task, TaskInput};
use crate::helper::gossip::publish_topic_message;
use crate::helper::store::Store;
use crate::helper::mem_store;
use crate::helper::cipher::{decrypt, encrypt};

pub trait RefreshAdaptor {
    fn new_task(&self, ctx: &mut Context, events: &SideEvent) -> Option<Vec<Task>>;
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(KeyPackage, PublicKeyPackage)>);
}

pub struct ParticipantRefresher<H> where H: RefreshAdaptor {
    name: String,
    handler: H,
}

impl<H> ParticipantRefresher<H> where H: RefreshAdaptor {
    pub fn new(name: impl Into<String>, handler: H) -> Self {
        Self {
            name: name.into(),
            handler,
        }
    }

    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(&self.name)
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn on_event(&self, ctx: &mut Context, event: &SideEvent) {
        if let Some(tasks) = self.handler.new_task(ctx, event) {
            self.execute(ctx, &tasks);
        }
    }

    pub fn execute(&self, ctx: &mut Context, tasks: &Vec<Task>) {
        tasks.iter().for_each(|task| {
            if ctx.task_store.exists(&task.id) { return }
            ctx.task_store.save(&task.id, &task);
            self.generate(ctx, &task);
        })
    }

}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RefreshInput {
    pub id: String,
    pub keys: Vec<String>,
    pub threshold: u16,
    pub remove_participants: Vec<Identifier>,
    pub new_participants: Vec<Identifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshMessage {
    pub sender: Identifier,
    pub payload: RefreshPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefreshPayload {
    Round1(Data<Vec<round1::Package>>),
    Round2(Data<Vec<BTreeMap<Identifier, Vec<u8>>>>)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct Data<T> where T: Serialize + DeserializeOwned{
    pub task_id: String,
    pub sender: Identifier,
    pub data: T,
}

impl<H> ParticipantRefresher<H> where H: RefreshAdaptor {

    fn broadcast_dkg_packages(&self, ctx: &mut Context, payload: RefreshPayload) {

        let raw = serde_json::to_vec(&payload).unwrap();
        let signature = ctx.node_key.sign(raw, None).to_vec();
        
        let msg = RefreshMessage{ sender: ctx.identifier, payload, signature };
        // debug!("Broadcasting: {:?}", msg);
        let bytes = serde_json::to_vec(&msg).expect("Failed to serialize DKG package");
        publish_topic_message(ctx, IdentTopic::new(&self.name), bytes);
    }

    pub fn generate(&self, ctx: &mut Context, task: &Task) {

        let refresh_input = match &task.input {
            TaskInput::REFRESH(i) => i,
            _ => return,
        };

        // make sure that all new participants have be added.
        if !refresh_input.new_participants.contains(&ctx.identifier) {
            return
        }

        metrics::counter!("refresh_start").increment(1);

        let mut packages = vec![];
        let mut secrets = vec![];
        for _k in refresh_input.keys.iter() {
            if let Ok((secret_packet, round1_package)) = frost::keys::refresh::refresh_dkg_part1(
                ctx.identifier.clone(),
                refresh_input.new_participants.len() as u16,
                refresh_input.threshold,
            ) {
                debug!("round1_secret_package: {:?} {}", task.id, _k );
                packages.push(round1_package);
                secrets.push(secret_packet);
            } else {
                error!("error in DKG round 1: {:?}", task.id);
            }
        };

        if secrets.len() == 0 {
            return
        }

        mem_store::set_dkg_round1_secret_packet(&task.id, secrets);
        // ctx.sec_round1.save(&task.id, &secrets);

        let data = Data{task_id: task.id.clone(), sender: ctx.identifier.clone(), data: packages};
        self.received_round1_packages(ctx, data.clone());
        self.broadcast_dkg_packages(ctx, RefreshPayload::Round1(data));
        
    }

    fn generate_round2_packages(&self, ctx: &mut Context, task: &Task, round1_packages: BTreeMap<Identifier, Vec<round1::Package>>) -> Result<(), DKGError> {

        let task_id = task.id.clone();

        // let secret_packages = match ctx.sec_round1.get(&task_id) {
        let secret_packages = match mem_store::get_dkg_round1_secret_packet(&task_id) {
            Some(secret_packet) => secret_packet,
            None => {
                return Err(DKGError(format!("No secret packet found for DKG: {}", task_id)));
            }
        };

        let refresh_input = match &task.input {
            TaskInput::REFRESH(i) => i,
            _ => return Err(DKGError(format!("Error Input: {}", task_id))),
        };

        // make sure that all new participants have be added.
        if !refresh_input.new_participants.contains(&ctx.identifier) {
            return Err(DKGError(format!("Not a new participant: {:?}", ctx.identifier)));
        }

        if refresh_input.new_participants.len() as u16 != round1_packages.len() as u16 {
            return Err(DKGError(format!("Have not received enough packages: {}", task_id)));
        }

        let mut cloned = round1_packages.clone();
        cloned.remove(&ctx.identifier);

        let mut secrets = vec![];
        let mut packages = vec![];
        let mut converted_round1_packages: Vec<BTreeMap<Identifier, round1::Package>> = vec![];

        cloned.iter().for_each(|(k, v)| {

            for (i, package) in v.iter().enumerate() {
                match converted_round1_packages.get_mut(i) {
                    Some(p) => {
                        p.insert(k.clone(), package.clone());
                    },
                    None => {
                        let mut m = BTreeMap::new();
                        m.insert(k.clone(), package.clone());
                        converted_round1_packages.push(m);
                    },
                };
            }
        });

        for (secret_package, round1_packages) in secret_packages.iter().zip(converted_round1_packages.iter()) {
            match frost::keys::refresh::refresh_dkg_part2(secret_package.clone(), round1_packages) {
                Ok((round2_secret_package, round2_packages)) => {
    
                    secrets.push(round2_secret_package);
                    // convert it to <receiver, Vec<u8>>, then only the receiver can decrypt it.
                    let mut output_packages = BTreeMap::new();
                    for (receiver_identifier, round2_package) in round2_packages {
                        let bz = receiver_identifier.serialize();
                        let target = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
            
                        let share_key = target.dh(&x25519::SecretKey::from_ed25519(&ctx.node_key).unwrap()).unwrap();
            
                        let byte = round2_package.serialize().unwrap();
                        let packet = encrypt(byte.as_slice(), share_key.as_slice().try_into().unwrap());
            
                        output_packages.insert(receiver_identifier, packet);
                    };

                    packages.push(output_packages);
                    // convert it to <sender, <receiver, Vec<u8>>
                    // let mut local = ctx.db_round2.get(&task_id).unwrap_or(BTreeMap::new()); 
                    // local.insert(ctx.identifier.clone(), vec![]); // use empty for local package
                }
                Err(e) => {
                    return Err(DKGError(e.to_string()));
                }
            };
        }

        if secrets.len() == 0 {
            return Err(DKGError("No package generated".to_string()))
        }

        mem_store::set_dkg_round2_secret_packet(&task_id, secrets);
        // ctx.sec_round2.save(&task_id, &secrets);
    
        let data  = Data{task_id, sender: ctx.identifier.clone(), data: packages};
        self.received_round2_packages(ctx, data.clone());

        self.broadcast_dkg_packages(ctx, RefreshPayload::Round2(data));

        Ok(())
    }

    pub fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        if message.topic.to_string() == self.name {
            let m = serde_json::from_slice(&message.data)?;
            self.received_dkg_message(ctx, m);
        }
        return Ok(())
    }

    fn received_dkg_message(&self, ctx: &mut Context, message: RefreshMessage) {

        // Ensure the message is not forged.
        match ed25519_compact::PublicKey::from_slice(&message.sender.serialize()) {
            Ok(public_key) => {
                let raw = serde_json::to_vec(&message.payload).unwrap();
                let sig = ed25519_compact::Signature::from_slice(&message.signature).unwrap();
                if public_key.verify(&raw, &sig).is_err() {
                    debug!("Reject, untrusted package from {:?}", message.sender);
                    return;
                }
            }
            Err(_) => return
        }

        match message.payload {
            RefreshPayload::Round1(data) => self.received_round1_packages(ctx, data),
            RefreshPayload::Round2(data) => self.received_round2_packages(ctx, data),
        }

    }

    fn received_round1_packages(&self, ctx: &mut Context, packets: Data<Vec<round1::Package>>) {

        let task_id = &packets.task_id;
        // store round 1 packets
        let mut local = ctx.db_round1.get(task_id).map_or(BTreeMap::new(), |v|v);
        if local.contains_key(&packets.sender) {
            // already received this sender's round1 package
            warn!("duplicated round1 package from {:?}: {}", mem_store::get_moniker(&packets.sender), task_id);
            return;
        }
        // merge packets with local
        local.insert(packets.sender, packets.data);
        ctx.db_round1.save(&task_id, &local);

        debug!("Received round1 packets: {} {:?}", &task_id, local.keys().map(|k| mem_store::get_participant_moniker(k)).collect::<Vec<_>>());

        let mut task = match ctx.task_store.get(&task_id) {
            Some(t) => t,
            None => return,
        };

        let refresh_input = match &task.input {
            TaskInput::REFRESH(i) => i,
            _ => return,
        };

        if !refresh_input.new_participants.contains(&packets.sender) {
            debug!("Received round1 package from unexpected participant: {:?} - {:?}", packets.sender, mem_store::get_participant_moniker(&packets.sender));
            return;
        }

        // Filter packages from valid participants.
        local.retain(|id, _| refresh_input.new_participants.contains(id));
        ctx.db_round1.save(&task_id, &local);

        if refresh_input.new_participants.len() == local.len() {
            
            info!("#{} round1 completed:", task_id);
            // let round1_packages = local.clone().iter().map(|(k, v)| { debug!("round1: {:?}", v); (k.clone(), v[0].clone()) }).collect::<BTreeMap<_,_>>();
            match self.generate_round2_packages(ctx,  &task, local) {
                Ok(_) => {
                    task.status = Status::Round2;
                    ctx.task_store.save(&task.id, &task);
                }
                Err(e) => {
                    task.status = Status::Complete;
                    // ctx.task_store.save(&task.id, &task);
                    error!("Failed to generate round2 packages: {} - {:?}", task.id, e);
                }
            }
            return;
        }
    }

    fn received_round2_packages(&self, ctx: &mut Context, packets: Data<Vec<BTreeMap<Identifier, Vec<u8>>>>) {

        let task_id = &packets.task_id;
        // store round 1 packets

        // Filter the packages where the recipient is me.
        let mut round2_packages = vec![];
        for received_package in packets.data {
            let bytes = match received_package.get(&ctx.identifier) {
                Some(t) => t.clone(),
                None => continue,
            };
            round2_packages.push(bytes);
        }

        let mut received = ctx.db_round2.get(task_id).unwrap_or(BTreeMap::new()); 
        if received.contains_key(&packets.sender) {
            // already received this sender's round2 package
            warn!("duplicated round2 package from {:?}: {}", mem_store::get_moniker(&packets.sender), task_id);
            return;
        }
        received.insert(packets.sender, round2_packages);
        ctx.db_round2.save(&task_id, &received);

        debug!("Received round2 packets: {} {:?}", task_id, received.keys().map(|k| mem_store::get_participant_moniker(k)).collect::<Vec<_>>());

        let mut task = match ctx.task_store.get(&task_id) {
            Some(t) => t,
            None => return,
        };

        let refresh_input = match &task.input {
            TaskInput::REFRESH(i) => i,
            _ => return,
        };

        if !refresh_input.new_participants.contains(&packets.sender) {
            debug!("Received round2 package from unexpected participant: {:?} - {:?}", packets.sender, mem_store::get_participant_moniker(&packets.sender));
            return;
        }

        // clean up the task if the sender is not in the new participants.
        if !refresh_input.new_participants.contains(&ctx.identifier) {
            ctx.db_round1.remove(task_id);
            ctx.db_round2.remove(task_id);
            ctx.clean_task_cache(task_id);
            return
        }

        // Filter packages from valid participants.
        received.retain(|id, _| refresh_input.new_participants.contains(id));

        if refresh_input.new_participants.len() == received.len() {

            info!("#{} round2 completed", task_id);

            // initialize a batch of empty BTreeMap.
            let mut batch = refresh_input.keys.iter().map(|i| (i.to_string(), BTreeMap::new()) ).collect::<Vec<_>>();
            
            // let mut round2_packages = BTreeMap::new();
            received.iter().filter(|(k, _)| *k != &ctx.identifier ).for_each(|(sender, packet)| {                
                let bz = sender.serialize();
                let source = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
                let share_key = source.dh(&x25519::SecretKey::from_ed25519(&ctx.node_key).unwrap()).unwrap();

                for ((_, round2_packages), p) in batch.iter_mut().zip(packet.iter()) {
                    let p = decrypt(p, share_key.as_slice().try_into().unwrap());
                    let received_round2_package = frost::keys::dkg::round2::Package::deserialize(&p).unwrap();
                    round2_packages.insert(sender.clone(), received_round2_package);
                }
            });

            let mut round1_packages = ctx.db_round1.get(task_id).unwrap_or(BTreeMap::new());

            // frost does not need its own package to compute the threshold key
            round1_packages.remove(&ctx.identifier);
            // let round2_secret_package = match ctx.sec_round2.get(task_id) {
            let round2_secret_package = match mem_store::get_dkg_round2_secret_packet(task_id) {
                Some(secret_package) => secret_package,
                None => {
                    error!("No secret packet found for DKG: {}", task_id);
                    return;
                }
            };

            let mut keys = vec![];
            batch.iter().zip(round2_secret_package.iter()).enumerate().for_each(|(i, ((store_key, round2_packages), round2_secret_package )) | {
                let old_key = match ctx.keystore.get(&store_key.to_string()) {
                    Some(k) => k,
                    None => return,
                };
                // extract the ith round1 package
                let mut ith_round1_packages = BTreeMap::new();
                for (k, v) in round1_packages.iter_mut() {
                    if v.len() >= i {
                        ith_round1_packages.insert(k.clone(), v[i].clone());
                    }
                }
                match frost::keys::refresh::refresh_dkg_shares(round2_secret_package, &ith_round1_packages, round2_packages, old_key.pub_key, old_key.priv_key) {
                    Ok((priv_key, pub_key)) => {
                        keys.push((priv_key, pub_key));
                    },
                    Err(e) => {
                        error!("Failed to compute threshold key: {} {:?}", task_id, e);
                        metrics::counter!("refresh_failure").increment(1);
                    }
                }; 
            });

            self.handler.on_complete(ctx, &mut task, keys);
            metrics::counter!("refresh_end").increment(1);
        }
    }
}

#[derive(Debug, Clone)]
pub struct DKGError(String);

impl fmt::Display for DKGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Use `self.number` to refer to each positional data point.
        write!(f, "dkg error: {}", self.0 )
    }
}

// impl DKGMessage {
//     pub fn sender(&self) -> String {
//         hex::encode(&self.sender.serialize())
//     }
// }
