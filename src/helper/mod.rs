
pub mod cipher;
pub mod encoding;
pub mod gossip;
pub mod mem_store;
pub mod bitcoin;
pub mod merkle_proof;
pub mod http;
pub mod client_bitcoin;
pub mod client_bitway;
pub mod client_ordinals;
pub mod client_fee_provider;
pub mod store;
pub mod websocket;

pub fn now() -> u64 {
    chrono::Utc::now().timestamp() as u64
}
