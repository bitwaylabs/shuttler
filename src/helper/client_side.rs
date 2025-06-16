
use std::str::FromStr;

use bitcoin::{hashes::{Hash, sha256d, HashEngine}, consensus::Encodable, key::Secp256k1, secp256k1::Message, sign_message::BITCOIN_SIGNED_MSG_PREFIX, PrivateKey};
use cosmrs::{ crypto::secp256k1::SigningKey, tx::{self, Fee, ModeInfo, Raw, SignDoc, SignerInfo, SignerPublicKey}, AccountId, Coin};
use cosmos_sdk_proto::{Any, cosmos::{
    base::{query::v1beta1::PageRequest, tendermint::v1beta1::{GetLatestBlockRequest, GetLatestValidatorSetRequest, GetLatestValidatorSetResponse}}, 
    tx::v1beta1::{service_client::ServiceClient as TxServiceClient, BroadcastMode, BroadcastTxRequest, BroadcastTxResponse}
}};
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient as TendermintServiceClient;
use frost_adaptor_signature::Identifier;
use tendermint::block::Height;
use tendermint_rpc::{endpoint, Client, HttpClient};
use tokio::sync::Mutex;
use tonic::{Response, Status};

use side_proto::side::{
    oracle::{
        query_client::QueryClient as OracleQueryClient, QueryBlockHeaderByHeightRequest, QueryBlockHeaderByHeightResponse, QueryChainTipRequest, QueryChainTipResponse
    },
    btcbridge::{
        query_client::QueryClient as BridgeQueryClient, QueryParamsRequest, QuerySigningRequestByTxHashRequest, QuerySigningRequestByTxHashResponse
    },
    tss::{
        query_client::QueryClient as TssQueryClient, QuerySigningRequestsRequest, QuerySigningRequestsResponse, SigningStatus, QueryParamsRequest as TssQueryParamsRequest, QueryParamsResponse as TssQueryParamsResponse
    },
    lending::{
        query_client::QueryClient as LendingQueryClient, QueryLoanDlcMetaRequest, QueryLoanDlcMetaResponse, QueryRedemptionRequest, QueryRedemptionResponse
    },
    liquidation::{
        query_client::QueryClient as LiquidationQueryClient, QueryLiquidationRequest, QueryLiquidationResponse
    },
};


use lazy_static::lazy_static;

use crate::{config, helper::mem_store};

lazy_static! {
    static ref lock: Mutex<()> = Mutex::new(());
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Pagination {
    pub limit: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequest {
    pub address: String,
    pub psbt: String,
    pub status: String,
    pub sequence: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequestsResponse {
    requests: Vec<SigningRequest>,
    pagination: Option<Pagination>,
}

impl SigningRequestsResponse {
    pub fn requests(&self) -> &Vec<SigningRequest> {
        &self.requests
    }

    pub fn pagination(&self) -> Option<&Pagination> {
        self.pagination.as_ref()
    }
}

// pub async fn connect_ws_client(endpoint: &str) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
// pub async fn connect_ws_client(endpoint: &str) -> TcpStream {

//     let sub_msg = r#"{"jsonrpc":"2.0","method":"subscribe","id":0,"params":{"query":"tm.event='NewBlock'"}}"#;
//     let host= format!("{}/websocket", endpoint.replace("http", "ws"));
    
//     tracing::info!("Connect... to {}", host);

//     // loop {
//     //     if let Ok(mut stream) = TcpStream::connect(endpoint.replace("http:://", "")) {
//     //         stream.set_read_timeout(Some(Duration::from_secs(5)));
//     //         stream.write(sub_msg.as_bytes());
//     //         return stream
//     //     }
//     // }

    
//     // let mut a: Option<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>> = None;
//     // let x = tokio::time::timeout(Duration::from_secs(5), connect_async(&host)).await
//     // loop {
//     //    match tokio::time::timeout(Duration::from_secs(5),connect_async(&host)).await {
//     //       Ok(Ok((mut ws_stream, _s))) => {
//     //         if ws_stream.send(WebSocketMessage::Text(sub_msg.into())).await.is_ok() {
//     //             // a = Some(ws_stream);
//     //             return ws_stream;
//     //         }
//     //       },
//     //       _ => thread::sleep(Duration::from_secs(5)),
//     //    };
//     // }
// }

pub async fn get_bitcoin_tip_on_side(host: &str) -> Result<Response<QueryChainTipResponse>, Status> {
    let mut client = match OracleQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    client.query_chain_tip(QueryChainTipRequest {}).await
}

pub async fn get_bitcoin_block_header_on_side(host: &str, height: u64) -> Result<Response<QueryBlockHeaderByHeightResponse>, Status> {
    let mut client = match OracleQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    client.query_block_header_by_height(QueryBlockHeaderByHeightRequest { height }).await
}

pub async fn get_confirmation_depth(host: &str) -> u64 {
    // TODO
    // use deposit confirmation depth for now
    get_deposit_confirmation_depth(host).await
}

pub async fn get_deposit_confirmation_depth(host: &str) -> u64 {
    let mut client = match BridgeQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(_) => {
            return 6 as u64;
        }
    };

    let res = match client.query_params(QueryParamsRequest{}).await {
        Ok(res) => res.into_inner(),
        Err(_) => {
            return 6 as u64;
        }
    };

    match res.params {
        Some(params) => { 
            return params.deposit_confirmation_depth as u64;
        }
        None => {
            return 6 as u64;
        }
    };
}

pub async fn get_withdraw_confirmation_depth(host: &str) -> u64 {
    let mut client = match BridgeQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(_) => {
            return 6 as u64;
        }
    };

    let res = match client.query_params(QueryParamsRequest{}).await {
        Ok(res) => res.into_inner(),
        Err(_) => {
            return 6 as u64;
        }
    };

    match res.params {
        Some(params) => { 
            return params.withdraw_confirmation_depth as u64;
        }
        None => {
            return 6 as u64;
        }
    };
}

pub async fn get_bridge_vaults (host: &str) -> anyhow::Result<Vec<String>> {
    let mut client = BridgeQueryClient::connect(host.to_string()).await?;
    let res = client.query_params(QueryParamsRequest {}).await?;

    match res.into_inner().params {
        Some(params) => Ok(params
            .vaults
            .iter()
            .map(|v| v.address.clone())
            .collect::<Vec<_>>()),
        None => Ok(vec![]),
    }
}

pub async fn get_latest_validators(host: &str) -> Result<Response<GetLatestValidatorSetResponse>, Status> {
    let mut client = match TendermintServiceClient::connect(host.to_string()).await {
        Ok(c) => c,
        Err(_) => {
            return Err(Status::cancelled(format!("Could not connect to {host}")));
        }
    };
    let mut page_request = PageRequest::default();
    page_request.limit = 100;
    client.get_latest_validator_set(GetLatestValidatorSetRequest{pagination: Some(page_request)}).await
}

pub async fn get_bridge_signing_request_by_txid(host: &str, txid: String) -> Result<Response<QuerySigningRequestByTxHashResponse>, Status> {
    let mut client = match BridgeQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    client.query_signing_request_by_tx_hash(QuerySigningRequestByTxHashRequest {
        txid,
    }).await
}

pub async fn get_bridge_pending_signing_requests(host: &str) -> Result<Response<side_proto::side::btcbridge::QueryPendingSigningRequestsResponse>, Status> {
    let mut client = match BridgeQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };
    
    client.query_pending_signing_requests(side_proto::side::btcbridge::QueryPendingSigningRequestsRequest{pagination: None}).await
}

pub async fn get_tss_signing_requests(host: &str) -> Result<Response<QuerySigningRequestsResponse>, Status> {
    let mut tss_client = match TssQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    tss_client.signing_requests(QuerySigningRequestsRequest {
        module: "".to_string(),
        status: SigningStatus::Pending as i32,
        pagination: None
    }).await
}

pub async fn get_tss_params(host: &str) -> Result<Response<TssQueryParamsResponse>, Status>  {
    let mut tss_client = match TssQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    tss_client.params(TssQueryParamsRequest{}).await
}

pub async fn get_tss_mosa_requests(host: &str) -> Result<Response<QuerySigningRequestsResponse>, Status> {
    let mut tss_client = match TssQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    tss_client.signing_requests(QuerySigningRequestsRequest {
        module: "".to_string(),
        status: SigningStatus::Signed as i32,
        pagination: None
    }).await
}

pub async fn get_loan_dlc_meta(host: &str, loan_id: String) -> Result<Response<QueryLoanDlcMetaResponse>, Status> {
    let mut client = match LendingQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create lending query client: {}", e)));
        }
    };

    client.loan_dlc_meta(QueryLoanDlcMetaRequest {
        loan_id,
    }).await
}

pub async fn get_redemption(host: &str, id: u64) -> Result<Response<QueryRedemptionResponse>, Status> {
    let mut client = match LendingQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create lending query client: {}", e)));
        }
    };

    client.redemption(QueryRedemptionRequest{
        id,
    }).await
}

pub async fn get_liquidation(host: &str, id: u64) -> Result<Response<QueryLiquidationResponse>, Status> {
    let mut client = match LiquidationQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create liquidation query client: {}", e)));
        }
    };

    client.liquidation(QueryLiquidationRequest {
        id,
    }).await
}

pub async fn get_latest_block(rpc: &str) -> Result<endpoint::block::Response, tendermint_rpc::Error> {
    let client = match HttpClient::new(rpc) {
        Ok(client) => client,
        Err(e) => {
            return Err(e);
        }
    };

    client.latest_block().await
}

pub async fn get_block_results(rpc: &str, height: u64) -> Result<endpoint::block_results::Response, tendermint_rpc::Error> {
    let client = match HttpClient::new(rpc) {
        Ok(client) => client,
        Err(e) => {
            return Err(e);
        }
    };

    let block_height = Height::try_from(height).expect("Should be able to be converted safely");
    client.block_results(block_height).await
}

pub async fn send_cosmos_transaction(identifier: &Identifier, conf: &config::Config, msg : Any) -> Result<tonic::Response<BroadcastTxResponse>, Status> {
    // let conf = shuttler.config();

    if conf.side_chain.grpc.is_empty() {
        return Err(Status::cancelled("GRPC URL is empty"));
        // return None;
    }

    // Generate sender private key.
    // In real world usage, this account would need to be funded before use.
    let sender_private_key = conf.relayer_bitcoin_privkey();
    // let sender_account_id = shuttler.relayer_address();

    ///////////////////////////
    // Building transactions //
    ///////////////////////////

    let _l = lock.lock().await;
    let base_account = config::get_relayer_account(conf).await;
    
    let mut base_client = match TendermintServiceClient::connect(conf.side_chain.grpc.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::aborted(format!("Failed to create tendermint client: {}", e)));
        }
    };

    let resp_b = match base_client.get_latest_block(GetLatestBlockRequest {
    }).await {
        Ok(resp) => resp,
        Err(e) => {
            return Err(Status::aborted(format!("Failed to get latest block: {}", e)));
        }
    };
    
    let chain_id = resp_b.into_inner().block.unwrap().header.unwrap().chain_id.parse().unwrap();
    let account_number = base_account.account_number;
    let sequence_number = base_account.sequence;
    let gas = conf.side_chain.gas;
    let mut fee = Fee::from_amount_and_gas(Coin::new(conf.side_chain.fee.amount as u128, conf.side_chain.fee.denom.as_str()).unwrap(), gas as u64);
    fee.granter = Some(AccountId::from_str("side1yjepcvxl7fredrxxythv6nq3w9walel3ktpkrw").unwrap());
    let timeout_height = 0u16;
    let memo = format!("TSS signer: {}", mem_store::get_participant_moniker(identifier));

    // Create transaction body from the MsgSend, memo, and timeout height.
    let tx_body = tx::Body::new(vec![msg].into_iter(), memo, timeout_height);

    let signing_key = SigningKey::from_slice(&sender_private_key.to_bytes()).unwrap();
    let mut any = signing_key.public_key().to_any().unwrap();
    any.type_url = "/cosmos.crypto.segwit.PubKey".to_string();
    let pubkey = SignerPublicKey::Any(any);
    let signer_info = SignerInfo {
        public_key: Some(pubkey),
        mode_info: ModeInfo::single(tx::SignMode::Direct),
        sequence: sequence_number,
    };

    // let signer_info = SignerInfo::single_direct(Some(signing_key.public_key()), sequence_number);
    // Compute auth info from signer info by associating a fee.
    let auth_info = signer_info.auth_info(fee);

    //////////////////////////
    // Signing transactions //
    //////////////////////////

    // The "sign doc" contains a message to be signed.
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number).unwrap();

    // Sign the "sign doc" with the sender's private key, producing a signed raw transaction.
    // let tx_signed = sign_doc.sign(&signing_key).unwrap();
    let tx_signed = sign_with_bitcoin_algo(&sign_doc, &sender_private_key);

    // Serialize the raw transaction as bytes (i.e. `Vec<u8>`).
    let tx_bytes = tx_signed.to_bytes().unwrap();

    let mut tx_client = match TxServiceClient::connect(conf.side_chain.grpc.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::aborted(format!("Failed to create tx client: {}", e)));
        }
    };

    match tx_client.broadcast_tx(BroadcastTxRequest {
        tx_bytes,
        mode: BroadcastMode::Sync.into(),    
    }).await {
        Ok(response) => {
            let tx_response = response.into_inner().tx_response;
            let tx_response_clone = tx_response.clone();
            if tx_response.is_some() && tx_response.unwrap().code == 0 {
                let mut new_account  = base_account.clone();
                new_account.sequence += 1;
                config::save_relayer_account(&new_account);
            }
            return Ok(tonic::Response::new(BroadcastTxResponse {
                tx_response: tx_response_clone,
            }));
        }
        Err(e) => {
            if e.message().contains("account sequence mismatch") {
                config::remove_relayer_account();
            }
            return Err(Status::aborted(format!("Failed to broadcast tx: {}", e)));
        }
    }
}

fn sign_with_bitcoin_algo(doc: &SignDoc, priv_key: &PrivateKey) -> Raw {
    let sign_doc_bytes = doc.clone().into_bytes().expect("Failed to serialize sign doc");
    let secp = Secp256k1::new();

    let msg_hash = signed_msg_hash(sign_doc_bytes);
    let msg = Message::from_digest(*msg_hash.as_byte_array());
    let signature = secp.sign_ecdsa_recoverable(&msg, &priv_key.inner);

    let mut sig_bytes: Vec<u8> = vec![];
    sig_bytes.push(signature.serialize_compact().0.to_i32() as u8 + 27 + 4);
    sig_bytes.append(&mut signature.serialize_compact().1.to_vec());

    cosmos_sdk_proto::cosmos::tx::v1beta1::TxRaw {
        body_bytes: doc.body_bytes.clone(),
        auth_info_bytes: doc.auth_info_bytes.clone(),
        signatures: vec![sig_bytes],
    }.into()
}

pub fn signed_msg_hash(msg: Vec<u8>) -> sha256d::Hash {
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    let msg_len = bitcoin::consensus::encode::VarInt::from(msg.len());
    msg_len.consensus_encode(&mut engine).expect("engines don't error");
    engine.input(msg.as_slice());
    sha256d::Hash::from_engine(engine)
}