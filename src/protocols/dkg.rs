

use core::fmt;
use std::{collections::BTreeMap, fmt::Debug};
use ed25519_compact::x25519;
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};
use libp2p::gossipsub::IdentTopic;
use rand::thread_rng;
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

pub trait DKGAdaptor {
    fn new_task(&self, ctx: &mut Context, events: &SideEvent) -> Option<Vec<Task>>;
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(KeyPackage, PublicKeyPackage)>);
}

pub struct DKG<H> where H: DKGAdaptor {
    name: String,
    handler: H,
}

impl<H> DKG<H> where H: DKGAdaptor {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGInput {
    pub id: String,
    pub participants: Vec<String>,
    pub threshold: u16,
    pub batch_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGMessage {
    pub sender: Identifier,
    pub payload: DKGPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKGPayload {
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

impl<H> DKG<H> where H: DKGAdaptor {

    fn broadcast_dkg_packages(&self, ctx: &mut Context, payload: DKGPayload) {

        let raw = serde_json::to_vec(&payload).unwrap();
        let signature = ctx.node_key.sign(raw, None).to_vec();
        
        let msg = DKGMessage{ sender: ctx.identifier, payload, signature };
        // debug!("Broadcasting: {:?}", msg);
        let bytes = serde_json::to_vec(&msg).expect("Failed to serialize DKG package");
        publish_topic_message(ctx, IdentTopic::new(&self.name), bytes);
    }

    pub fn generate(&self, ctx: &mut Context, task: &Task) {

        let dkg_input = match &task.input {
            TaskInput::DKG(i) => i,
            _ => return
        };

        if dkg_input.participants.len() < 3 || !dkg_input.participants.contains(&ctx.identifier){
            return;
        }

        let mut rng = thread_rng();
        let mut payload_data = vec![];
        let mut secrets = vec![];
        for _i in 0..dkg_input.batch_size {
            if let Ok((secret_packet, round1_package)) = frost::keys::dkg::part1(
                ctx.identifier.clone(),
                dkg_input.participants.len() as u16,
                dkg_input.threshold,
                &mut rng,
            ) {
                // debug!("round1_secret_package: {:?}", &task.id);
                // mem_store::set_dkg_round1_secret_packet(&store_key, secret_packet);
                secrets.push(secret_packet);

                let mut round1_packages = BTreeMap::new();
                round1_packages.insert(ctx.identifier.clone(), round1_package.clone());

                payload_data.push(round1_package);

            } else {
                error!("error in DKG round 1: {:?}", task.id);
                return;
            }
        }

        if payload_data.len() == 0 {
            error!("No round1 package generated: {}", task.id);
            return;
        }

        // save the round1 secret packages
        // mem_store::set_dkg_round1_secret_packet(&task.id, secrets);
        ctx.sec_round1.save(&task.id, &secrets);
        // ctx.db_round1.save(&task.id, &payload_data);

        let data = Data{task_id: task.id.clone(), sender: ctx.identifier.clone(), data: payload_data};
        // broadcast the round1 packages
        self.received_round1_packages(ctx, data.clone()); // broadcast to self
        self.broadcast_dkg_packages(ctx, DKGPayload::Round1(data)); // broadcast to all
    }

    fn generate_round2_packages(&self, ctx: &mut Context, task: &Task, round1_packages: BTreeMap<Identifier, Vec<round1::Package>>) -> Result<(), DKGError> {

        let task_id = task.id.clone();

        let secret_packages = match ctx.sec_round1.get(&task_id) {
            Some(secret_packet) => secret_packet,
            None => {
                return Err(DKGError(format!("No secret packet found for DKG: {}", task_id)));
            }
        };

        let dkg_input = match &task.input {
            TaskInput::DKG(i) => i,
            _ => return Err(DKGError("umatched input".to_string()))
        };

        if dkg_input.participants.contains(&ctx.identifier) == false {
            return Err(DKGError(format!("not in participants of {}", task_id)));
        }

        if dkg_input.participants.len() as u16 != round1_packages.len() as u16 {
            return Err(DKGError(format!("Have not received enough packages: {}", task_id)));
        }

        if round1_packages.values().any(|v| v.len() != secret_packages.len()) {
            return Err(DKGError(format!("Invalid round1 packages: {} package length not match", task_id)));
        }

        let mut cloned = round1_packages.clone();
        cloned.remove(&ctx.identifier);

        let mut round2_secret_packages = vec![];
        let mut round2_public_packages = vec![];
        for (i, secret_package) in secret_packages.iter().enumerate() {
            // extract the ith round1 package
            let mut ith_round1_packages = BTreeMap::new();
            for (k, v) in cloned.iter_mut() {
                if v.len() >= i {
                    ith_round1_packages.insert(k.clone(), v[i].clone());
                }
            }

            match frost::keys::dkg::part2(secret_package.clone(), &ith_round1_packages) {
                Ok((round2_secret_package, round2_packages)) => {
                    // mem_store::set_dkg_round2_secret_packet(&task_id, round2_secret_package);
                    round2_secret_packages.push(round2_secret_package);
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
    
                    // convert it to <sender, <receiver, Vec<Vec<u8>>>
                    round2_public_packages.push(output_packages);
                }
                Err(e) => {
                    return Err(DKGError(e.to_string()));
                }
            };
        }
        if round2_secret_packages.len() == 0 {
            return Err(DKGError(format!("No round2 package generated: {}", task_id)));
        }
        // store the round2 secret packages
        // mem_store::set_dkg_round2_secret_packet(&task_id, round2_secret_packages);
        ctx.sec_round2.save(&task_id, &round2_secret_packages);
        let data  = Data{task_id, sender: ctx.identifier.clone(), data: round2_public_packages};
        // self.received_round2_packages(ctx, data.clone()); // broadcast to self
        self.broadcast_dkg_packages(ctx, DKGPayload::Round2(data)); // broadcast to all others
        Ok(())
    }

    pub fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        if message.topic.to_string() == self.name {
            let m = serde_json::from_slice(&message.data)?;
            self.received_dkg_message(ctx, m);
        }
        // if let Ok(m) =  H::message(message) {
        //     self.received_dkg_message(ctx, m);
        // }
        return Ok(())
    }

    fn received_dkg_message(&self, ctx: &mut Context, message: DKGMessage) {

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
            DKGPayload::Round1(data) => self.received_round1_packages(ctx, data),
            DKGPayload::Round2(data) => self.received_round2_packages(ctx, data),
        }

    }

    fn received_round1_packages(&self, ctx: &mut Context, packets: Data<Vec<round1::Package>>) {

        let task_id = &packets.task_id;
        // store round 1 packets
        let mut received = ctx.db_round1.get(task_id).map_or(BTreeMap::new(), |v|v);
        
        if received.contains_key(&packets.sender) {
            // reject duplicated round1 package
            warn!("duplicated round1 package from {:?}: {}", packets.sender, task_id);
            return;
        }

        // merge packets with local
        received.insert(packets.sender, packets.data);

        match ctx.task_store.get(&task_id) {
            None => {
                ctx.db_round1.save(&task_id, &received);
                return
            },
            Some(mut task) => {
                let dkg_input = match &task.input {
                    TaskInput::DKG(i) => i,
                    _ => return
                };

                if !dkg_input.participants.contains(&packets.sender) {
                    return;
                }

                if !dkg_input.participants.contains(&ctx.identifier) {
                    ctx.clean_dkg_cache(&task_id);
                    debug!("Received round1 package from {:?} but not a participant in task: {}", packets.sender, task_id);
                    return;
                } else {
                    debug!("Received round1 packets: {} {:?}", &task_id, received.keys().map(|k| mem_store::get_participant_moniker(k)).collect::<Vec<_>>());
                }

                received.retain(|id, _| dkg_input.participants.contains(id));
                ctx.db_round1.save(&task_id, &received);
                
                if dkg_input.participants.len() == received.len() {
            
                    info!("#{} round1 completed", task_id);
                    match self.generate_round2_packages(ctx,  &task, received) {
                        Ok(_) => {
                            task.status = Status::Round2;
                            ctx.task_store.save(&task.id, &task);
                        }
                        Err(e) => {
                            task.status = Status::Complete;
                            ctx.task_store.save(&task.id, &task);
                            error!("Failed to generate round2 packages: {} - {:?}", task.id, e);
                        }
                    }
                    return;
                }
            },
        };

    }

    fn received_round2_packages(&self, ctx: &mut Context, packets: Data<Vec<BTreeMap<Identifier, Vec<u8>>>>) {

        let task_id = &packets.task_id;

        let mut received_round2_package = vec![];

        // filter data that receiver is the current participant
        for round2_data in packets.data {    
            let data = match round2_data.get(&ctx.identifier) {
                Some(t) => t.clone(),
                None => return,
            };
            received_round2_package.push(data);
        }

        let mut received = ctx.db_round2.get(task_id).unwrap_or(BTreeMap::new()); 
        if received.contains_key(&packets.sender) {
            // already received this sender's round1 package
            warn!("duplicated round2 package from {:?}: {}", packets.sender, task_id);
            return;
        }
        received.insert(packets.sender, received_round2_package);

        match ctx.task_store.get(&task_id) {
            None => {
                ctx.db_round2.save(&task_id, &received);
            },
            Some(mut task) => {

                let dkg_input = match &task.input {
                    TaskInput::DKG(i) => i,
                    _ => return
                };

                if !dkg_input.participants.contains(&packets.sender) {
                    return;
                }

                if !dkg_input.participants.contains(&ctx.identifier) {
                    ctx.clean_dkg_cache(&task_id);
                    debug!("Received round1 package from {:?} but not a participant in task: {}", packets.sender, task_id);
                    return;
                } else {
                    debug!("Received round2 packets: {} {:?}", task_id, received.keys().map(|k| mem_store::get_participant_moniker(k)).collect::<Vec<_>>()); 
                }
                received.retain(|id, _| dkg_input.participants.contains(id));

                ctx.db_round2.save(&task_id, &received);

                if dkg_input.participants.len() == received.len() + 1 {
                    // info!("Received round2 packets from all participants: {}", task.id);

                    // initialize a batch of empty BTreeMap.
                    let mut batch = (0..dkg_input.batch_size).map(|_i| BTreeMap::new() ).collect::<Vec<_>>();
                    
                    // let mut round2_packages = BTreeMap::new();
                    received.iter().filter(|(k, _)| *k != &ctx.identifier ).for_each(|(sender, packet)| {
                        
                        let bz = sender.serialize();
                        let source = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
                        let share_key = source.dh(&x25519::SecretKey::from_ed25519(&ctx.node_key).unwrap()).unwrap();

                        for (round2_packages, p) in batch.iter_mut().zip(packet.iter()) {
                            let p = decrypt(p, share_key.as_slice().try_into().unwrap());
                            let received_round2_package = frost::keys::dkg::round2::Package::deserialize(&p).unwrap();
                            round2_packages.insert(sender.clone(), received_round2_package);
                        }

                    });

                    info!("#{} round2 completed", task_id);

                    // compute the threshold key
                    let round2_secret_package = match ctx.sec_round2.get(task_id) {
                        Some(secret_package) => secret_package,
                        None => {
                            error!("No secret packet found for DKG: {}", task_id);
                            return;
                        }
                    };

                    let mut round1_packages = ctx.db_round1.get(task_id).unwrap_or(BTreeMap::new());

                    // frost does not need its own package to compute the threshold key
                    round1_packages.remove(&ctx.identifier);

                    let mut keys = vec![];
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
                                keys.push((priv_key, pub_key));
                            },
                            Err(e) => {
                                error!("Failed to compute threshold key: {} {:?}", task_id, e);
                            }
                        }; 
                    });

                    self.handler.on_complete(ctx, &mut task, keys);
            
                }
            }
        };
        
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
