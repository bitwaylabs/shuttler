
use std::sync::Arc;

use axum::{routing::get, Router};
use tracing::info;

use crate::{apps::Task, helper::store::DefaultStore};

pub mod service;

pub use service::*;

#[derive(Clone)]
pub struct AppState {
    pub task_store: Arc<DefaultStore<String, Task>>,
    pub recorder:  metrics_prometheus::Recorder,
    
}

impl AppState {
    pub fn new(task_store: Arc<DefaultStore<String, Task>>, recorder:  metrics_prometheus::Recorder ) -> Self {
        Self { task_store, recorder }
    }
}

pub async fn run_rpc_server(rpc: String, task_store: Arc<DefaultStore<String, Task>>) -> std::result::Result<(), std::io::Error>{

    let recorder =  metrics_prometheus::install();

    metrics::counter!("signing_failure").absolute(0);
    metrics::counter!("dkg_failure").absolute(0);
    metrics::counter!("refresh_failure").absolute(0);

    let state2 = AppState::new(task_store, recorder);
    // let shared_state = Arc::new(Context{});
    
    let app = Router::new()
        // .route("/address", get(addresses))
        .route("/metrics", get(metrics))
        // .route("path", get( async { let x= db.get(&"ss".to_string()); return "hello metrics"}))
        .route("/health", get(health))
        .route("/peers", get(peers))
        // .layer(Extension(state2))
        .with_state(state2)
        .route("/", get(home));
    info!("Starting RPC Server({})...", rpc);
    let listener = tokio::net::TcpListener::bind(rpc).await.expect("RPC Port is unavailable.");
    
    axum::serve(listener, app).await

}