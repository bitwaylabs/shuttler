

use frost_adaptor_signature::Identifier;
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::{Deserialize, Serialize};

use crate::{apps::{Context, Shuttler, ShuttlerBehaviour}, config::{BLOCK_HEIGHT, HEART_BEAT_DURATION, VERSION}};

use super::{mem_store, now, store::Store};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SubscribeTopic {
    HEARTBEAT,
}

impl SubscribeTopic {
    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(format!("{:?}", self))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartBeatMessage {
    pub payload: HeartBeatPayload,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartBeatPayload {
    pub identifier: Identifier,
    pub last_seen: u64,
    pub block_height: u64,
    pub v: Option<String>,
}

pub fn subscribe_gossip_topics(swarm: &mut Swarm<ShuttlerBehaviour>, app: &Shuttler) {
    let mut topics = vec![
        SubscribeTopic::HEARTBEAT.topic(),
    ];
    app.apps.iter().for_each(|a| topics.extend(a.subscribe_topics()));

    for topic in topics {
        swarm.behaviour_mut().gossip.subscribe(&topic).expect("Failed to subscribe TSS events");
    }
}

pub fn sending_heart_beat(ctx: &mut Context, block_height: u64) {

        ctx.general_store.save(&BLOCK_HEIGHT, &block_height.to_string());

        let last_seen = now() + HEART_BEAT_DURATION.as_secs();
        let payload = HeartBeatPayload {
            identifier: ctx.identifier.clone(),
            last_seen,
            block_height,
            v: Some(VERSION.to_string()),
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let signature = ctx.node_key.sign(bytes, None).to_vec();
        let alive = HeartBeatMessage { payload, signature };
        let message = serde_json::to_vec(&alive).unwrap();
        publish_message(ctx, SubscribeTopic::HEARTBEAT, message);
        
        mem_store::update_alive_table(&ctx.identifier, alive);
}

pub fn publish_message(ctx: &mut Context, topic: SubscribeTopic, message: Vec<u8>) {
    match ctx.swarm.behaviour_mut().gossip.publish(topic.topic(), message) {
        Ok(_) => { },
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}

pub fn publish_topic_message(ctx: &mut Context, topic: IdentTopic, message: Vec<u8>) {
    match ctx.swarm.behaviour_mut().gossip.publish(topic.clone(), message) {
        Ok(_) => { },
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}





