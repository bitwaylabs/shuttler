use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::{GetLatestValidatorSetResponse, Validator};
use lending::{handle_signature_submission, handle_lending_dkg_submission, lending_task_queue};
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_server::Query as AuthService;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_server::Service as TxService;
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_server::Service as BlockService;
use cosmos_sdk_proto::tendermint::types::{Block, Header};

use cosmrs::{Any, Tx};

use bitcoin::{hashes::{sha256d, Hash},
    opcodes, psbt::PsbtSighashType, transaction::Version, Amount, OutPoint, Psbt, Sequence, TxIn,
    TxOut, Address, ScriptBuf, Transaction, Txid
};
use tendermint::abci::EventAttribute;
use tendermint::block::Height;

use crate::apps::SideEvent;
use crate::helper::cipher::random_bytes;
use crate::helper::encoding::to_base64;

use crate::helper::now;

mod bridge;
mod lending;
pub mod websocket;
pub use bridge::*;

type EventQueue = BTreeMap<u64, fn(MockEnv, Height) -> SideEvent>;

pub const SINGING_FILE_NAME: &str = "signing-requests.json";
pub const BRIDGE_DKG_FILE_NAME: &str = "dkg-request.json";
pub const VAULT_FILE_NAME: &str = "address.txt";

pub fn generate_event_queue(module: &String) -> EventQueue {
    if module == "bridge" {
        bridge_task_queue()
    } else if module == "lending" {
        lending_task_queue()
    } else {
        lending_task_queue()
    }
}

// pub fn exit_queue(_: MockEnv) -> SideEvent {
//     // exit(0);
//     // panic!("completed queue.");

// }

fn handle_tx_submissions(home: &str, tx_num: u32, tx_bytes: &Vec<u8>) {
    if let Ok(tx) = Tx::from_bytes(tx_bytes) {
        tx.body.messages.iter().for_each(|m| {
            if m.type_url == "/side.btcbridge.MsgCompleteDKG" {
                handle_bridge_dkg_submission(home, tx_num, m);
            } else if m.type_url == "/side.tss.MsgCompleteDKG" {
                handle_lending_dkg_submission(home, m);
            } else if m.type_url == "/side.tss.MsgSubmitSignatures" {
                handle_signature_submission(home, m);
            } else {
                println!("Received msg: {}", m.type_url);
            }
        })
    }
}

pub fn extact_value(attr: &Vec<EventAttribute>, key: &str) -> Option<String> {
    for i in attr {
        if let Ok(k) = i.key_str() {
            if k == key {
                if let Ok(s) = i.value_str() {
                    return Some(s.to_string())
                }
            }
        }
    }
    None
}

#[derive(Clone)]
pub struct MockEnv {
    home: String,
    module: String, 
    participants: Vec<String>,
}

impl MockEnv {
    pub fn new(home: String, module: String, participants: Vec<String>) -> Self {
        let x = if participants.len() > 3 {
            participants[1..].to_vec()
        } else {
            participants
        };
        Self {
            home,
            module,
            participants: x,
        }
    }
}

#[derive(Clone)]
pub struct MockQuery {
    pub home: String,
}
pub struct MockTxService {
    pub home: String,
    pub tx: u32,
}

pub struct MockBlockService {
    validators: Vec<Validator>,
}

impl MockBlockService {
    pub fn new(validators: Vec<Validator>) -> Self {
        Self {
            validators
        }
    }
    async fn mock_latest_validator_sets(&self) -> Result<tonic::Response<GetLatestValidatorSetResponse>, tonic::Status> {
        let res  = GetLatestValidatorSetResponse { 
            block_height: 0,
            validators: self.validators.clone(), 
            pagination: None 
        };
        Ok(tonic::Response::new(res))
    }
}

impl MockQuery {
    pub fn new(home: String) -> Self {
        Self {
            home,
        }
    }
    pub fn fullpath(&self, file: &str) -> PathBuf {
        fullpath(&self.home, file)
    }
}

fn fullpath(home: &str, file: impl AsRef<Path>) -> PathBuf {
    let mut path = PathBuf::new();
    path.push(home);
    path.push("mock");
    let _ = fs::create_dir_all(&path);
    path.push(file);
    path
}
// produce mock data

async fn loading_account(address: String) -> Result<tonic::Response<QueryAccountResponse>, tonic::Status> {
    let mut ba = BaseAccount::default();
    ba.address = address;
    let res = QueryAccountResponse {
        account: Some(Any::from_msg(&ba).unwrap()),
    };
    Ok(tonic::Response::new(res))
}

async fn mock_broadcast_tx() -> Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxResponse>, tonic::Status> {
    Ok(tonic::Response::new(cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxResponse {
        tx_response: Some(TxResponse::default())
    }))
}

async fn mock_latest_block() -> Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse>, tonic::Status> {
    
    let mut header = Header::default();
    header.chain_id = "mock-testnet".to_owned();
    header.height = 123;
    header.time = Some(cosmos_sdk_proto::tendermint::google::protobuf::Timestamp {
        seconds: now() as i64,
        nanos: 0
    });
    
    let res = cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse {
        block_id: None,
        block: Some(Block {
            header: Some(header),
            data: None,
            evidence: None,
            last_commit: None,
        }),
        sdk_block: None,
    };
    Ok(tonic::Response::new(res))
}

// implementing gRPC services
impl AuthService for MockQuery {
    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn accounts<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn account<'life0,'async_trait>(&'life0 self,request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let addr = request.get_ref().address.clone();
        let x = loading_account(addr);
        Box::pin(x)
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn account_address_by_id<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountAddressByIdRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountAddressByIdResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn params<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryParamsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryParamsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn module_accounts<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn module_account_by_name<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountByNameRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountByNameResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn bech32_prefix<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::Bech32PrefixRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::Bech32PrefixResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn address_bytes_to_string<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressBytesToStringRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressBytesToStringResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn address_string_to_bytes<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressStringToBytesRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressStringToBytesResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn account_info<'life0,'async_trait>(&'life0 self, _request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountInfoRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountInfoResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}

impl TxService for MockTxService {
    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn simulate<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::SimulateRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::SimulateResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_tx<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn broadcast_tx<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        handle_tx_submissions(self.home.as_str(), self.tx, &_request.get_ref().tx_bytes);

        let x = mock_broadcast_tx();
        Box::pin(x)
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_txs_event<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxsEventRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxsEventResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_block_with_txs<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::GetBlockWithTxsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::GetBlockWithTxsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn tx_decode<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::TxDecodeRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::TxDecodeResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn tx_encode<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::TxEncodeRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::TxEncodeResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn tx_encode_amino<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::TxEncodeAminoRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::TxEncodeAminoResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn tx_decode_amino<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::TxDecodeAminoRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::TxDecodeAminoResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}

impl BlockService for MockBlockService {
    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_node_info<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetNodeInfoRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetNodeInfoResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_syncing<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetSyncingRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetSyncingResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_latest_block<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockRequest>) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let x = mock_latest_block();
        Box::pin(x)
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_block_by_height<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetBlockByHeightRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetBlockByHeightResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_latest_validator_set<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestValidatorSetRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestValidatorSetResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        Box::pin(self.mock_latest_validator_sets())
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_validator_set_by_height<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetValidatorSetByHeightRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetValidatorSetByHeightResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn abci_query<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::AbciQueryRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::AbciQueryResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}

fn generate_mock_psbt(addr: &str, input_num: Option<u32>) -> (String, String) {
    let address = Address::from_str(addr).unwrap().assume_checked();
    
    let num = match input_num {
        Some(num) => num,
        None => 1
    };

    let sequence: u32 = (1 << 31) + 0xde;

    let mut inputs = Vec::<TxIn>::new();
    for i in 0..num {
        let hash = sha256d::Hash::hash(&random_bytes(12));
        let tx_in = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(hash),
                vout: i,
            },
            sequence: Sequence(sequence),
            ..Default::default()
        };

        inputs.push(tx_in);
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: [TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::builder()
                .push_opcode(opcodes::all::OP_RETURN)
                .into_script(),
        }]
        .to_vec(),
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx.clone()).unwrap();

    psbt.inputs.iter_mut().for_each(|input| {
        input.sighash_type = Some(PsbtSighashType::from_u32(0));
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: address.script_pubkey(),
        })
    });

    let tx_id = unsigned_tx.compute_txid().to_string();
    let psbt_b64 = to_base64(psbt.serialize().as_slice());

    (tx_id, psbt_b64)
}

