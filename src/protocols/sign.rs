use std::collections::BTreeMap;

use bitcoin::hex::DisplayHex;
use frost_adaptor_signature::{round1::{self, Nonce, SigningNonces}, round2::{self, SignatureShare}, Field, Identifier, Secp256K1ScalarField, SigningPackage};
use libp2p::gossipsub::IdentTopic;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
pub use tracing::error;
use usize as Index;
use crate::{apps::{Context, FrostSignature, SideEvent, SignMode, Status, SubscribeMessage, Task, TaskInput}, config::{VaultKeypair, TASK_INTERVAL}, 
    helper::{
        bitcoin::convert_tweak, gossip::publish_topic_message, mem_store, now, store::Store
}};

use ed25519_compact::{PublicKey, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignMessage {
    pub task_id: String,
    pub package: SignPackage,
    pub sender: Identifier,
    pub signature: Vec<u8>,
    pub key: String,
    pub create_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignPackage {
    Commitment(BTreeMap<Index,BTreeMap<Identifier,round1::SigningCommitments>>,),
    Snapshot(BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>),
    SignatureShare(BTreeMap<Index,BTreeMap<Identifier,round2::SignatureShare>>),
}

impl SignPackage {
    fn to_name(&self) -> &'static str {
        match &self {
            SignPackage::Commitment(_) => "Commitment",
            SignPackage::Snapshot(_) => "Comitment Snapshot",
            SignPackage::SignatureShare(_) => "Signature Share",
        }
    }
}

pub trait SignAdaptor {
    fn new_task(&self, ctx: &mut Context, events: &SideEvent) -> Option<Vec<Task>>;
    fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()>;
}

#[derive(Clone)]
pub struct StandardSigner<H: SignAdaptor> {
    name: String,
    handler: H,
}

impl<H> StandardSigner<H> where H: SignAdaptor{

    pub fn new(name: impl Into<String>, handler: H) -> Self {
        Self {name: name.into(), handler}
    }

    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(&self.name)
    }

    pub fn on_event(&self, ctx: &mut Context, event: &SideEvent){
        if let Some(tasks) = self.handler.new_task(ctx, event) {
            self.execute(ctx, &tasks);
        }
    }

    pub fn execute(&self, ctx: &mut Context, tasks: &Vec<Task>) {
        tasks.iter().for_each(|task| {
            if ctx.task_store.exists(&task.id) { return }
            ctx.task_store.save(&task.id, &task);
            self.generate_commitments(ctx, &task);
        });
    }
    
    pub fn generate_commitments(&self, ctx: &mut Context, task: &Task) {

        if task.status == Status::Complete {
            return
        }

        let sign_inputs = match &task.input {
            TaskInput::SIGN(i) => i,
            _ => return
        };

        debug!("Start a new signing task: {}, {}", task.id, sign_inputs.len());

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        //let mut commitments = signer.get_signing_commitments(&task.id);

        let signing_key = match sign_inputs.first() {
            Some(i) => i.key.clone(),
            None => return,
        };
        let key = match ctx.keystore.get(&signing_key) {
            Some(k) => k,
            None => return,
        };

        sign_inputs.iter().enumerate().for_each(|(index, _input)| {
            let mut rng = thread_rng();
            let (nonce, commitment) = round1::commit(key.priv_key.signing_share(), &mut rng);
            nonces.insert(index, nonce);
            let mut input_commit = BTreeMap::new();
            input_commit.insert(ctx.identifier.clone(), commitment);
            commitments.insert(index, input_commit.clone());
        });

        if nonces.len() ==0 {
            return
        }

        // Save nonces to local storage.
        ctx.nonce_store.save(&task.id, &nonces);

        // Publish commitments to other pariticipants
        let mut msg =  SignMessage {
            task_id: task.id.clone(),
            package: SignPackage::Commitment(commitments),
            sender: ctx.identifier.clone(),
            signature: vec![],
            key: signing_key,
            create_time: task.time,
        };

        self.broadcast_signing_packages(ctx, &mut msg);

        self.received_sign_message(ctx, msg);

        metrics::counter!("signing_start").increment(1);
    }


    pub fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        if message.topic.to_string() == self.name {
            let m = serde_json::from_slice(&message.data)?;
            self.received_sign_message(ctx, m);
        }
        return Ok(())
    }

    fn received_sign_message(&self, ctx: &mut Context, msg: SignMessage) {

        // check if I am one of participants
        let signing_key = match ctx.keystore.get(&msg.key) {
            Some(k) => k,
            None => return,
        };

        // Check if the message from the expected participants.
        if !signing_key.pub_key.verifying_shares().contains_key(&msg.sender) {
            return
        }

        // tracing:: debug!("Received: {:?}", msg);
        // Ensure the message is not forged.
        match PublicKey::from_slice(&msg.sender.serialize()) {
            Ok(public_key) => {
                let raw = serde_json::to_vec(&msg.package).unwrap();
                let sig = Signature::from_slice(&msg.signature).unwrap();
                if public_key.verify(&raw, &sig).is_err() {
                    debug!("Reject, untrusted package from {:?}", mem_store::get_moniker(&msg.sender));
                    return;
                }
            }
            Err(e) => {
                debug!("Received invalid message: {}", e);
                return
            }
        }

        match &msg.package {
            SignPackage::Commitment(commitments) => {

                let mut remote_commitments = ctx.commitment_store.get(&msg.task_id).unwrap_or(BTreeMap::new());

                // merge received package
                commitments.iter().for_each(|(index, incoming)| {
                    match remote_commitments.get_mut(index) {
                        Some(existing) => {
                            existing.extend(incoming);
                        },
                        None => {
                            remote_commitments.insert(*index, incoming.clone());
                        },
                    }
                });

                ctx.commitment_store.save(&msg.task_id, &remote_commitments);

                self.coordinate_commitments(ctx, &msg, &signing_key, &remote_commitments);

            },
            SignPackage::Snapshot(commitments) => {
                let coordinator = select_coordinator(&signing_key.pub_key.verifying_shares().keys().collect::<Vec<_>>(), msg.create_time);
                if msg.sender != coordinator {
                    error!("Received commitment snapshot from {:?}, but expected from {:?} ", mem_store::get_moniker(&msg.sender), mem_store::get_moniker(&coordinator));
                    return
                }
                self.generate_signature_shares(ctx,  &msg, &signing_key, commitments);
            },
            SignPackage::SignatureShare(sig_shares) => {

                let mut remote_sig_shares = ctx.signature_store.get(&msg.task_id).unwrap_or(BTreeMap::new());

                // Merge all signature shares
                sig_shares.iter().for_each(|(index, incoming)| {
                    match remote_sig_shares.get_mut(index) {
                        Some(existing) => {
                            existing.extend(incoming);
                        },
                        None => {
                            remote_sig_shares.insert(*index, incoming.clone());
                        }
                    }
                });

                ctx.signature_store.save(&msg.task_id, &remote_sig_shares);

                self.try_aggregate_signature_shares(ctx, &msg.task_id, &signing_key, &remote_sig_shares);
                
            }
        }
    }

    fn coordinate_commitments(&self,ctx: &mut Context, msg: &SignMessage, signing_key: &VaultKeypair, stored_remote_commitments: &BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>) {

        let coordinator = select_coordinator(&signing_key.pub_key.verifying_shares().keys().collect::<Vec<_>>(), msg.create_time);
        if ctx.identifier != coordinator {
            return
        }

        let signing_commitments = match stored_remote_commitments.get(&0) {
            Some(e) => e,
            None => return
        };

        // Only check the first one, because all inputs are in the same package
        if signing_commitments.len() != *signing_key.priv_key.min_signers() as usize {
            return
        }

        let mut msg = SignMessage {
            task_id: msg.task_id.clone(),
            package: SignPackage::Snapshot(stored_remote_commitments.to_owned()),
            sender: ctx.identifier.clone(),
            signature: vec![],
            key: msg.key.clone(),
            create_time: msg.create_time,
        };

        self.broadcast_signing_packages(ctx, &mut msg);

        self.received_sign_message(ctx, msg);

    }

    fn generate_signature_shares(&self, ctx: &mut Context, msg: &SignMessage, signing_key: &VaultKeypair, received_commitments: &BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let task = match ctx.task_store.get(&msg.task_id) {
            Some(t) => t,
            None => return,
        };

        let stored_nonces = ctx.nonce_store.get(&task.id).unwrap_or_default();
        if stored_nonces.len() == 0 {
            return;
        }
        
        let sign_inputs = match &task.input {
            TaskInput::SIGN(i) => i,
            _ => return
        };

        let min_signers = *signing_key.priv_key.min_signers() as usize;
        let mut broadcast_packages = BTreeMap::new();

        for (index, input) in sign_inputs.iter().enumerate() {

            let signing_commitments = match received_commitments.get(&index) {
                Some(e) => e.clone(),
                None => return
            };

            // I am not selected
            if index == 0 && !signing_commitments.contains_key(&ctx.identifier) {
                return
            }

            if signing_commitments.len() != min_signers {
                tracing::error!("Received invalid commitment: {:?}", signing_commitments);
                return
            }
            
            let signing_package = SigningPackage::new(
                signing_commitments, 
                &input.message,
            );

            let signer_nonces = match &input.mode {
                SignMode::SignWithGroupcommitment(gc) => {

                    let key_b = match gc.serialize() {
                        Ok(b) => b,
                        Err(_) => return,
                    };
                    
                    let nonce = match ctx.keystore.get(&key_b[1..].to_lower_hex_string()) {
                        Some(t) => t,
                        None => {
                            error!("Group Commitment Not Found: {}", key_b.to_lower_hex_string());
                            return;
                        },
                    };
            
                    let hiding = Nonce::from_scalar(nonce.priv_key.signing_share().to_scalar());
                    let binding = Nonce::from_scalar(Secp256K1ScalarField::zero());
            
                    &SigningNonces::from_nonces(hiding, binding)
                }, 
                _ => {
                    match stored_nonces.get(&index) {
                        Some(d) => d,
                        None => {
                            debug!("not found local nonce for input {index}");
                            return;
                        },
                    }
                }};

            let signature_shares = match sign(&input.mode, &signing_key, &signing_package, signer_nonces) {
                Ok(s) => s,
                Err(e) => {
                    error!("Sign error: {}", e);
                    return;
                },
            };
            
            let mut my_share = BTreeMap::new();
            my_share.insert(ctx.identifier.clone(), signature_shares);
            
            // broadcast my share
            broadcast_packages.insert(index.clone(), my_share.clone());
        
        };

        if broadcast_packages.len() == 0 {
            return;
        }

        let mut msg = SignMessage {
            task_id: task.id.clone(),
            package: SignPackage::SignatureShare(broadcast_packages),
            sender: ctx.identifier.clone(),
            signature: vec![],
            key: msg.key.clone(),
            create_time: msg.create_time,
        };

        self.broadcast_signing_packages(ctx, &mut msg);

        self.received_sign_message(ctx, msg);

    }

    fn try_aggregate_signature_shares(&self, ctx: &mut Context, task_id: &String, signing_key: &VaultKeypair, stored_remote_signature_shares: &BTreeMap<Index, BTreeMap<Identifier, round2::SignatureShare>>) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let mut task = match ctx.task_store.get(task_id) {
            Some(t) => t,
            None => return,
        };

        if task.status == Status::Complete {
            return
        }

        let stored_remote_commitments = ctx.commitment_store.get(&task.id).unwrap_or_default();
        
        let mut verifies = vec![];
        let mut sign_inputs = match task.input.clone() {
            TaskInput::SIGN(i) => i,
            _ => return
        };

        let threshold = signing_key.priv_key.min_signers().clone() as usize;

        for (index, input) in sign_inputs.iter_mut().enumerate() {

            let signature_shares = match stored_remote_signature_shares.get(&index) {
                Some(e) => e.clone(),
                None => return
            };

            if signature_shares.len() < threshold {
                return
            }

            let mut signing_commitments = match stored_remote_commitments.get(&index) {
                Some(e) => e.clone(),
                None => return
            };

            signing_commitments.retain(|k, _v| {signature_shares.contains_key(k)});

            if index == 0 {
                debug!("Signature share {} {}/{}", &task_id, signature_shares.len(), signing_commitments.len() )
            }
            
            let signing_package = SigningPackage::new(
                signing_commitments,
                &input.message
            );

            match aggregate(&signing_package, &signature_shares, &signing_key, &input.mode) {
                Ok(s) => {
                    verifies.push(true);
                    input.signature = Some(s);
                },
                Err(e) => {
                    error!("aggregate error: {}", e);
                    metrics::counter!("signing_failure").increment(1);
                    return
                }
            };
        };

        if verifies.len() ==0 {
            return
        }

        let output  = verifies.iter().enumerate()
                            .map(|(i, v)| format!("{i}:{}", if *v {"✔"} else {"✘"}))
                            .collect::<Vec<_>>().join(" ");
        info!("Verify {}: {}", &task.id, output );

        task.status = Status::Complete;
        task.input = TaskInput::SIGN(sign_inputs);
        ctx.task_store.save(&task.id, &task);
        
        if let Err(e) = self.handler.on_complete(ctx, &mut task) {
            error!("signing error: {:?}", e);
            metrics::counter!("signing_failure").increment(1);
        } else {
            metrics::counter!("signing_end").increment(1);
        }

    }

    fn broadcast_signing_packages(&self, ctx: &mut Context, message: &mut SignMessage) {
        let raw = serde_json::to_vec(&message.package).unwrap();
        let signature = ctx.node_key.sign(raw, None).to_vec();
        message.signature = signature;
    
        tracing::info!("Broadcast {}: {:?}", message.package.to_name(), message.task_id);
        let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
        publish_topic_message(ctx, self.topic(), message);
    }

}


fn sign(mode: &SignMode, keypair: &VaultKeypair, signing_package: &SigningPackage, signer_nonces: &SigningNonces) -> anyhow::Result<SignatureShare>  {
    match mode {
        SignMode::Sign => {
            Ok(round2::sign(signing_package, signer_nonces, &keypair.priv_key)?)
        },
        SignMode::SignWithTweak => {
            let tweek  = convert_tweak(&keypair.tweak);
            Ok(round2::sign_with_tweak(
                signing_package, signer_nonces, &keypair.priv_key, tweek
            )?)
        },
        SignMode::SignWithGroupcommitment(group_commitment) => {
            // let group_commitment = hex_to_projective_point(group)?;
            Ok(round2::sign_with_dkg_nonce(signing_package, signer_nonces, &keypair.priv_key, &group_commitment)?)
        },
        SignMode::SignWithAdaptorPoint(adaptor_point) => {
            // adatpor signature
            Ok(round2::sign_with_adaptor_point(
                signing_package, signer_nonces, &keypair.priv_key, &adaptor_point,
            )?)
        },
    }
}

fn aggregate(signing_package: &SigningPackage, signature_shares: &BTreeMap<Identifier, SignatureShare>, keypair: &VaultKeypair, mode: &SignMode) -> anyhow::Result<FrostSignature>  {

    match mode {
        SignMode::SignWithTweak => {
            let tweek  = convert_tweak(&keypair.tweak);
            let signature = frost_adaptor_signature::aggregate_with_tweak(&signing_package, signature_shares, &keypair.pub_key, tweek)?;
            Ok(FrostSignature::Standard(signature))
        },
        SignMode::SignWithGroupcommitment(group_commitment) => {
            let frost_signature = frost_adaptor_signature::aggregate_with_group_commitment(&signing_package, signature_shares, &keypair.pub_key, &group_commitment)?;
            Ok(FrostSignature::Standard(frost_signature))
        },
        SignMode::SignWithAdaptorPoint(adaptor_point) => {
            let frost_signature = frost_adaptor_signature::aggregate_with_adaptor_point(&signing_package, signature_shares, &keypair.pub_key, adaptor_point)?;
            Ok(FrostSignature::Adaptor(frost_signature))
        }
        _ => {
            let frost_signature = frost_adaptor_signature::aggregate(&signing_package, signature_shares, &keypair.pub_key)?;
            Ok(FrostSignature::Standard(frost_signature))
        }
    }

}

fn select_coordinator(all_participants: &Vec<&Identifier>, time: u64) -> Identifier {

    let du = ((now() - time) / TASK_INTERVAL) as usize % all_participants.len(); 
    all_participants[du].clone()

}