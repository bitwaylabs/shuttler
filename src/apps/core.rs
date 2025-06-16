use bitcoincore_rpc::{Auth, Client as BitcoinClient};
use cosmrs::Any;
use ed25519_compact::SecretKey;
use frost_adaptor_signature::{round1, round2, AdaptorSignature, Identifier, Signature};
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use std::sync::mpsc::Sender;
use tendermint::abci::Event as TxEvent;

use crate::{
    apps::ShuttlerBehaviour,
    config::{Config, VaultKeypair},
    helper::{
        encoding::to_base64,
        now,
        store::{DefaultStore, Store},
    }, protocols::refresh::RefreshInput,
};

pub type SubscribeMessage = libp2p::gossipsub::Message;

#[derive(Debug, Clone)]
pub enum SideEvent {
    BlockEvent(BTreeMap<String, Vec<String>>),
    TxEvent(Vec<TxEvent>)
}

pub trait App {
    fn name(&self) -> String;
    fn subscribe_topics(&self) -> Vec<IdentTopic>;
    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>;
    fn on_event(&self, ctx: &mut Context, event: &SideEvent);
    fn execute(&self, ctx: &mut Context, task: Vec<Task>) -> anyhow::Result<()>;
}

pub mod event {
    use crate::helper::encoding::to_base64;
    use tendermint::abci::{Event, EventAttribute};

    pub fn has_event_value(events: &Vec<Event>, value: &str) -> bool {
        events.iter().any(|e| has_attribute_value(&e.attributes, value))
    }

    pub fn get_event_value(events: &Vec<Event>, kind: &str, key: &str) -> Option<String> {
        events.iter().find(|e| e.kind == kind).map(|e| get_attribute_value(&e.attributes, key))?
    }

    pub fn has_attribute_value(attr: &Vec<EventAttribute>, value: &str) -> bool {
        attr.iter()
            .find(|ea| match ea {
                EventAttribute::V037(event_attribute) => &event_attribute.value == value,
                EventAttribute::V034(_) => false,
            })
            .is_some()
    }

    pub fn get_attribute_value(attr: &Vec<EventAttribute>, key: &str) -> Option<String> {
        attr.iter()
            .find(|ea| match ea {
                EventAttribute::V037(event_attribute) => &event_attribute.key == key,
                EventAttribute::V034(_) => false,
            })
            .map(|a| match a {
                EventAttribute::V037(event_attribute) => event_attribute.value.to_string(),
                EventAttribute::V034(event_attribute) => to_base64(&event_attribute.value),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Round1,
    Round2,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignMode {
    Sign,
    SignWithTweak,
    SignWithGroupcommitment(frost_adaptor_signature::VerifyingKey),
    SignWithAdaptorPoint(frost_adaptor_signature::VerifyingKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrostSignature {
    Standard(Signature),
    Adaptor(AdaptorSignature),
}

impl FrostSignature {
    pub fn inner(&self) -> &Signature {
        match self {
            FrostSignature::Standard(signature) => signature,
            FrostSignature::Adaptor(adaptor_signature) => &adaptor_signature.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub key: String,
    pub participants: Vec<Identifier>,
    pub index: usize,
    pub mode: SignMode,
    pub message: Vec<u8>,
    pub signature: Option<FrostSignature>,
}

impl Input {
    pub fn new(sign_key: String) -> Self {
        Self {
            index: 0,
            participants: vec![],
            key: sign_key,
            mode: SignMode::Sign,
            message: vec![],
            signature: None,
        }
    }

    pub fn new_with_message(
        sign_key: String,
        message: Vec<u8>,
        participants: Vec<Identifier>,
    ) -> Self {
        Self::new_with_message_mode(sign_key, message, participants, SignMode::SignWithTweak)
    }

    pub fn new_with_message_mode(
        sign_key: String,
        message: Vec<u8>,
        participants: Vec<Identifier>,
        mode: SignMode,
    ) -> Self {
        Self {
            index: 0,
            participants,
            key: sign_key,
            mode,
            message,
            signature: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DkgInput {
    pub participants: Vec<Identifier>,
    pub threshold: u16,
    pub tweaks: Vec<i32>,
    pub batch_size: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskInput {
    DKG(DkgInput),
    SIGN(Vec<Input>),
    REFRESH(RefreshInput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub status: Status,
    pub time: u64,
    pub input: TaskInput,
    pub memo: String, // store psbt for later use
    pub submitted: bool,
}

impl Task {
    pub fn new_dkg(id: String, participants: Vec<Identifier>, threshold: u16, batch_size: usize) -> Self {
       Task::new_dkg_with_args(id, participants, threshold, vec![], batch_size)
    }

    pub fn new_dkg_with_tweak(id: String, participants: Vec<Identifier>, threshold: u16, tweaks: Vec<i32>) -> Self {
       Task::new_dkg_with_args(id, participants, threshold, tweaks, 1)
    }

    pub fn new_dkg_with_args(id: String, participants: Vec<Identifier>, threshold: u16, tweaks: Vec<i32>, batch_size: usize) -> Self {
        Self::new_with_input(id, TaskInput::DKG(DkgInput {
            participants,
            threshold,
            tweaks,
            batch_size,
        }), "".to_owned())
    }

    pub fn new_signing(
        id: String,
        memo: impl Into<String>,
        sign_inputs: Vec<Input>,
    ) -> Self {
        Self::new_with_input(id, TaskInput::SIGN(sign_inputs), memo)
    }

    pub fn new_with_input(id: String, input: TaskInput, memo: impl Into<String>) -> Self {
        Self { id, status: Status::Round1, time: now(), input, memo: memo.into(), submitted: false }
    }
    
}
type Index = usize;
type CommitmentStore =
    DefaultStore<String, BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>>;
type SignatureShareStore =
    DefaultStore<String, BTreeMap<Index, BTreeMap<Identifier, round2::SignatureShare>>>;
type SignerNonceStore = DefaultStore<String, BTreeMap<Index, round1::SigningNonces>>;

pub type Round1Store =
    DefaultStore<String, BTreeMap<Identifier, Vec<frost_adaptor_signature::keys::dkg::round1::Package>>>;
pub type Round2Store = DefaultStore<String, BTreeMap<Identifier, Vec<Vec<u8>>>>;


pub type Round1SecetStore = DefaultStore<String, Vec<frost_adaptor_signature::keys::dkg::round1::SecretPackage>>;
pub type Round2SecetStore = DefaultStore<String, Vec<frost_adaptor_signature::keys::dkg::round2::SecretPackage>>;

pub struct Context {
    pub swarm: Swarm<ShuttlerBehaviour>,
    pub tx_sender: Sender<Any>,
    pub identifier: Identifier,
    pub node_key: SecretKey,
    pub id_base64: String,
    pub conf: Config,
    pub keystore: DefaultStore<String, VaultKeypair>,
    pub task_store: Arc<DefaultStore<String, Task>>,
    pub nonce_store: SignerNonceStore,
    pub commitment_store: CommitmentStore,
    pub signature_store: SignatureShareStore,
    pub general_store: DefaultStore<&'static str, String>,
    // pub price_store: Arc<PriceStore>,
    pub bitcoin_client: BitcoinClient,

    // dkg stores
    pub db_round1: Round1Store,
    pub db_round2: Round2Store,
    pub sec_round1: Round1SecetStore,
    pub sec_round2: Round2SecetStore,
}

impl Context {
    pub fn new(
        swarm: Swarm<ShuttlerBehaviour>,
        tx_sender: Sender<Any>,
        identifier: Identifier,
        node_key: SecretKey,
        conf: Config,
    ) -> Self {
        let id_base64 = to_base64(&identifier.serialize());
        let auth = if !conf.bitcoin.user.is_empty() {
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone())
        } else {
            Auth::None
        };

        let bitcoin_client = BitcoinClient::new(&conf.bitcoin.rpc, auth)
            .expect("Could not initial bitcoin RPC client");

        Self {
            bitcoin_client,
            swarm,
            tx_sender,
            identifier,
            node_key,
            id_base64,
            keystore: DefaultStore::new(conf.get_database_with_name("keypairs")),
            task_store: Arc::new(DefaultStore::new(conf.get_database_with_name("tasks"))),
            nonce_store: SignerNonceStore::new(conf.get_database_with_name("nonces")),
            commitment_store: CommitmentStore::new(conf.get_database_with_name("commitments")),
            signature_store: SignatureShareStore::new(conf.get_database_with_name("signature_shares")),
            general_store: DefaultStore::new(conf.get_database_with_name("general")),

            db_round1: Round1Store::new(conf.get_database_with_name("round1")),
            db_round2: Round2Store::new(conf.get_database_with_name("round2")),
            sec_round1: Round1SecetStore::new(conf.get_database_with_name("sec_round1")),
            sec_round2: Round2SecetStore::new(conf.get_database_with_name("sec_round2")),

            conf,

        }
    }

    pub fn clean_dkg_cache(&self, task_id: &String) {
        self.db_round1.remove(task_id);
        self.db_round2.remove(task_id);
        self.sec_round1.remove(task_id);
        self.sec_round2.remove(task_id);
    }

    pub fn clean_task_cache(&self, task_id: &String) {
        self.task_store.remove(task_id);
        self.nonce_store.remove(task_id);
        self.commitment_store.remove(task_id);
        self.signature_store.remove(task_id);
        // self.db_round1.remove(task_id);
        // self.db_round2.remove(task_id);
    }
}
