use std::str::FromStr;

use frost_adaptor_signature::Identifier;
use libp2p::PeerId;
use tracing::{debug, warn};

use crate::helper::{client_bitway, encoding::{from_base64, identifier_to_peer_id, pubkey_to_identifier}, mem_store, now};

#[derive(Debug)]
pub struct Candidate {
    last_sync_time: u64,
    host: String,
    identifiers: Vec<Identifier>,
    peers: Vec<PeerId>,
    bootstraps: Vec<String>,
}

impl Candidate {
    pub fn new(host: String, bootstraps: &Vec<String>) -> Self {
        let mut peers = vec![];
        bootstraps.iter().for_each(|p| 
            if let Some(pid_str) = p.split("/").last() {
                if let Ok(pid) = PeerId::from_str(pid_str) {
                    peers.push(pid);
                }
            }
        );
        Self {
            last_sync_time: 0,
            host,
            identifiers: vec![],
            peers,
            bootstraps: bootstraps.clone(),
        }
    }

    pub fn has_bootstrap_nodes(&self) -> bool {
        self.bootstraps.len() > 0
    }

    pub async fn sync_from_validators(&mut self, ) {
        // hourly update
        if self.last_sync_time + 3600 > now() { 
            return 
        }

        let params = match client_bitway::get_tss_params(&self.host).await {
            Ok(r) => r.into_inner().params.unwrap(),
            Err(e) => {
                warn!("failed to sync valdiators: {:?}", e);
                return
            },
        };

        self.last_sync_time = now();

        self.peers.clear();
        self.identifiers.clear();

        params.allowed_dkg_participants.iter().for_each(|v| {
            if let Ok(pk ) = from_base64(&v.consensus_pubkey) {
                let id = pubkey_to_identifier(&pk);
                debug!("Access granted to {} {}", v.consensus_pubkey, v.moniker);
                mem_store::add_moniker(&id, v.moniker.clone());
                self.peers.push(identifier_to_peer_id(&id ));
                self.identifiers.push( id );
            }
        });

        metrics::counter!("total_participants").absolute(self.identifiers.len() as u64);
    }

    pub fn identifiers(&self) -> &Vec<Identifier> {
        &self.identifiers
    }

    pub fn peers(&self) -> &Vec<PeerId> {
        &self.peers
    }
}
