

use std::sync::Arc;

use axum::{extract::State, Json};
use frost_adaptor_signature::Identifier;

use crate::helper::{mem_store, store::Store};

pub async fn home() -> &'static str  {
    "Welcome to Shuttler"
}

pub async fn health() -> &'static str {
    "OK"
}
pub async fn metrics(State(state): State<super::AppState>) -> String {
    // let list= state.task_store.list();

    match prometheus::TextEncoder::new().encode_to_string(&state.recorder.registry().gather()) {
        Ok(report) => report,
        Err(e) => format!("Error occurs in report generation : {e}"),
    }
    
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Peers {
    pub count: usize,
    pub address: Vec<Identifier>,
}

pub async fn peers() -> Json<Peers> {
    let participants = mem_store::alive_participants();
    Json(Peers {
        count: participants.len(),
        address: participants,
    })
}

pub async fn addresses(_state: Arc<super::AppState>) -> &'static str {
    // ...
    "hello metrics"
}