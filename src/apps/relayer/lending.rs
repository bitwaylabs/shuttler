use bitcoin::{
    consensus::{encode, Decodable},
    Block, BlockHash, Network, Transaction, Txid,
};
use bitcoincore_rpc::RpcApi;
use futures::join;
use tendermint::abci;
use tendermint_rpc::endpoint;
use tokio::time::{sleep, Duration};
use tonic::{Response, Status};
use tracing::{debug, error, info};

use crate::{
    apps::relayer::Relayer,
    helper::{
        bitcoin::{self as bitcoin_utils, get_signed_tx_from_psbt},
        client_side::{
            self, get_liquidation, get_loan_dlc_meta, get_redemption, send_cosmos_transaction,
        },
        encoding::to_base64,
    },
};

use cosmos_sdk_proto::{cosmos::tx::v1beta1::BroadcastTxResponse, Any};
use side_proto::side::{lending::MsgSubmitDepositTransaction, liquidation::LiquidationStatus};

const EVENT_TYPE_APPLY: &str = "apply";
const EVENT_ATTRIBUTE_KEY_VAULT: &str = "vault";

const EVENT_TYPE_GENERATE_SIGNED_CET: &str = "generate_signed_cet";
const EVENT_ATTRIBUTE_KEY_LOAN_ID: &str = "loan_id";
const EVENT_ATTRIBUTE_KEY_CET_TYPE: &str = "cet_type";
const _EVENT_ATTRIBUTE_KEY_TX_HASH: &str = "tx_hash";

const EVENT_TYPE_GENERATE_SIGNED_REDEMPTION_TRANSACTION: &str =
    "generate_signed_redemption_transaction";
const EVENT_ATTRIBUTE_KEY_ID: &str = "id";

const EVENT_TYPE_GENERATE_SIGNED_SETTLEMENT_TRANSACTION: &str =
    "generate_signed_settlement_transaction";
const EVENT_ATTRIBUTE_KEY_LIQUIDATION_ID: &str = "liquidation_id";

const DB_KEY_SIDE_BLOCK_HEIGHT: &str = "side_block_height";
const DB_KEY_BITCOIN_BLOCK_HEIGHT: &str = "bitcoin_block_height";
const DB_KEY_VAULT_PREFIX: &str = "vault";

pub async fn start_relayer_tasks(relayer: &Relayer) {
    join!(scan_blocks_on_side(&relayer), scan_txs_on_bitcoin(&relayer),);
}

pub async fn scan_blocks_on_side(relayer: &Relayer) {
    let interval = 6;

    loop {
        let height = get_last_scanned_height_side(relayer) + 1;

        let latest_block_height =
            match client_side::get_latest_block(&relayer.config.side_chain.rpc).await {
                Ok(resp) => resp.block.header.height.value(),
                Err(e) => {
                    error!("Failed to get the latest block: {}", e);

                    sleep(Duration::from_secs(interval)).await;
                    continue;
                }
            };

        if height > latest_block_height {
            debug!(
                "No new side blocks to sync, height: {}, latest height: {}",
                height, latest_block_height
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

        scan_side_blocks_by_range(relayer, height, latest_block_height).await;
    }
}

pub async fn scan_txs_on_bitcoin(relayer: &Relayer) {
    let interval = relayer.config().loop_interval;

    loop {
        let height = get_last_scanned_height_bitcoin(relayer) + 1;

        let tip_on_bitcoin = match relayer.bitcoin_client.get_block_count() {
            Ok(height) => height,
            Err(e) => {
                error!("Failed to get the block count: {}", e);
                continue;
            }
        };

        if height > tip_on_bitcoin {
            debug!(
                "No new bitcoin txs to sync, height: {}, bitcoin tip: {}, sleep for {} seconds",
                height, tip_on_bitcoin, interval
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

        let side_tip =
            match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
                Ok(res) => res.get_ref().height,
                Err(e) => {
                    error!("Failed to get tip from side chain: {}", e);

                    sleep(Duration::from_secs(interval)).await;
                    continue;
                }
            };

        let confirmations =
            client_side::get_confirmation_depth(&relayer.config().side_chain.grpc).await;
        if side_tip < confirmations || height > side_tip - confirmations + 1 {
            debug!(
                "No new bitcoin txs to sync, height: {}, side tip: {}, sleep for {} seconds...",
                height, side_tip, interval
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

        debug!(
            "Scanning bitcoin height: {:?}, side tip: {:?}",
            height, side_tip
        );
        scan_bitcoin_txs_by_height(relayer, height).await;
        save_last_scanned_height_bitcoin(relayer, height);
    }
}

pub async fn scan_side_blocks_by_range(relayer: &Relayer, start_height: u64, end_height: u64) {
    let interval = 6;

    let mut current_height = start_height;

    while current_height <= end_height {
        debug!("Scanning side height: {}", current_height);

        let block_results_resp =
            match client_side::get_block_results(&relayer.config.side_chain.rpc, current_height)
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    error!(
                        "Failed to get the block results: {}, err: {}",
                        current_height, e
                    );

                    sleep(Duration::from_secs(interval)).await;
                    continue;
                }
            };

        on_side_block(relayer, block_results_resp).await;

        save_last_scanned_height_side(relayer, current_height);
        current_height += 1;
    }
}

async fn on_side_block(relayer: &Relayer, block_results_resp: endpoint::block_results::Response) {
    parse_and_save_vaults(relayer, block_results_resp.clone().txs_results);
    parse_and_handle_cets(relayer, block_results_resp.clone().finalize_block_events).await;
    parse_and_handle_redemption_txs(relayer, block_results_resp.clone().txs_results).await;
    parse_and_handle_settlement_txs(relayer, block_results_resp.clone().txs_results).await;
}

fn parse_and_save_vaults(relayer: &Relayer, txs_results: Option<Vec<abci::types::ExecTxResult>>) {
    txs_results.unwrap_or(vec![]).iter().for_each(|result| {
        result.events.iter().for_each(|event| {
            if event.kind == EVENT_TYPE_APPLY {
                event.attributes.iter().for_each(|attr| {
                    if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_VAULT {
                        let vault = attr.value_str().unwrap().to_string();

                        debug!("Vault found on side: {}", vault);
                        save_vault(relayer, vault);
                    }
                })
            };
        });
    })
}

async fn parse_and_handle_cets(relayer: &Relayer, finalize_block_events: Vec<abci::Event>) {
    let mut loan_ids = vec![];
    let mut cet_types = vec![];

    finalize_block_events.iter().for_each(|event| {
        if event.kind == EVENT_TYPE_GENERATE_SIGNED_CET {
            event.attributes.iter().for_each(|attr| {
                if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_LOAN_ID {
                    let loan_id = attr.value_str().unwrap().to_string();

                    debug!("Signed cet found on side, loan id: {}", loan_id);
                    loan_ids.push(loan_id);
                }

                if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_CET_TYPE {
                    let cet_type = attr.value_str().unwrap().to_string();

                    debug!("Signed cet type: {}", cet_type);
                    cet_types.push(cet_type);
                }
            })
        };
    });

    for (i, loan_id) in loan_ids.iter().enumerate() {
        handle_cet(relayer, loan_id.to_string(), cet_types[i].clone()).await;
    }
}

async fn parse_and_handle_redemption_txs(
    relayer: &Relayer,
    txs_results: Option<Vec<abci::types::ExecTxResult>>,
) {
    let mut redemption_ids: Vec<u64> = vec![];

    txs_results.unwrap_or(vec![]).iter().for_each(|result| {
        result.events.iter().for_each(|event| {
            if event.kind == EVENT_TYPE_GENERATE_SIGNED_REDEMPTION_TRANSACTION {
                event.attributes.iter().for_each(|attr| {
                    if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_ID {
                        let id = attr.value_str().unwrap().parse().unwrap();

                        debug!("Signed redemption tx found on side, id: {}", id,);
                        redemption_ids.push(id);
                    }
                });
            };
        });
    });

    for id in redemption_ids {
        handle_redemption_tx(relayer, id).await;
    }
}

async fn parse_and_handle_settlement_txs(
    relayer: &Relayer,
    txs_results: Option<Vec<abci::types::ExecTxResult>>,
) {
    let mut liquidation_ids = vec![];

    txs_results.unwrap_or(vec![]).iter().for_each(|result| {
        result.events.iter().for_each(|event| {
            if event.kind == EVENT_TYPE_GENERATE_SIGNED_SETTLEMENT_TRANSACTION {
                event.attributes.iter().for_each(|attr| {
                    if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_LIQUIDATION_ID {
                        let liquidation_id = attr.value_str().unwrap().parse().unwrap();

                        debug!(
                            "Signed liquidation settlement tx found on side, liquidation id: {}",
                            liquidation_id,
                        );
                        liquidation_ids.push(liquidation_id);
                    }
                });
            };
        });
    });

    for liquidation_id in liquidation_ids {
        handle_liquidation_settlement_tx(relayer, liquidation_id).await;
    }
}

pub async fn scan_bitcoin_txs_by_height(relayer: &Relayer, height: u64) {
    let block_hash = match relayer.bitcoin_client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to get block hash: {:?}, err: {:?}", height, e);
            return;
        }
    };

    let block = match relayer.bitcoin_client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", height, e);
            return;
        }
    };

    for (i, tx) in block.txdata.iter().enumerate() {
        debug!(
            "Checking tx {:?}, height: {:?}, index: {:?}",
            tx.compute_txid(),
            height,
            i
        );

        check_and_handle_bitcoin_tx(relayer, &block_hash, &block, tx, i).await
    }
}

pub async fn check_and_handle_bitcoin_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    block: &Block,
    tx: &Transaction,
    index: usize,
) {
    if is_deposit_tx(relayer, tx, relayer.config().bitcoin.network) {
        let vault = get_vault(relayer, tx, relayer.config().bitcoin.network);
        debug!(
            "Deposit tx found on bitcoin: {}, vault: {}",
            tx.compute_txid(),
            vault
        );

        let proof = bitcoin_utils::compute_tx_proof(
            block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
            index,
        );

        match send_deposit_tx(relayer, vault, tx, block_hash, proof).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to submit deposit tx to side: {:?}", tx_response);
                    return;
                }

                info!("Submitted deposit tx to side: {:?}", tx_response);
            }
            Err(e) => {
                error!("Failed to submit deposit tx to side: {:?}", e);
            }
        }

        return;
    }
}

pub async fn check_and_handle_bitcoin_tx_by_hash(relayer: &Relayer, hash: &Txid) {
    let tx_info = match relayer.bitcoin_client.get_raw_transaction_info(&hash, None) {
        Ok(tx_info) => tx_info,
        Err(e) => {
            error!("Failed to get the raw tx info: {}, err: {}", hash, e);

            return;
        }
    };

    let tx = match tx_info.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to get the raw tx: {}, err: {}", hash, e);

            return;
        }
    };

    let block_hash = match tx_info.blockhash {
        Some(block_hash) => block_hash,
        None => {
            error!("Failed to get the block hash of the tx: {}", hash);
            return;
        }
    };

    let block = match relayer.bitcoin_client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", &block_hash, e);
            return;
        }
    };

    let tx_index = block
        .txdata
        .iter()
        .position(|tx_in_block| tx_in_block == &tx)
        .expect("the tx should be included in the block");

    check_and_handle_bitcoin_tx(relayer, &block_hash, &block, &tx, tx_index).await
}

pub async fn send_deposit_tx(
    relayer: &Relayer,
    vault: String,
    tx: &Transaction,
    block_hash: &BlockHash,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitDepositTransaction {
        relayer: relayer.config().relayer_bitcoin_address(),
        vault,
        deposit_tx: to_base64(encode::serialize(tx).as_slice()),
        block_hash: block_hash.to_string(),
        proof,
    };

    info!("submit deposit tx to side: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(&relayer.identifier, &relayer.config(), any_msg).await
}

pub async fn handle_cet(relayer: &Relayer, loan_id: String, cet_type: String) {
    let dlc_meta = match get_loan_dlc_meta(&relayer.config.side_chain.grpc, loan_id.clone()).await {
        Ok(resp) => match resp.into_inner().dlc_meta {
            Some(dlc_meta) => dlc_meta,
            None => {
                error!("No dlc meta exists on side, loan id: {}", loan_id);
                return;
            }
        },
        Err(e) => {
            error!("Failed to query dlc meta, loan id: {}, err: {}", loan_id, e);
            return;
        }
    };

    let signed_tx_hex = match cet_type.as_str() {
        "0" => dlc_meta.liquidation_cet.unwrap_or_default().signed_tx_hex,
        "1" => {
            dlc_meta
                .default_liquidation_cet
                .unwrap_or_default()
                .signed_tx_hex
        }
        "2" => dlc_meta.repayment_cet.unwrap_or_default().signed_tx_hex,
        _ => "".to_string(),
    };

    if signed_tx_hex.is_empty() {
        error!(
            "Cet not signed yet, loan id: {}, cet type: {}",
            loan_id, cet_type
        );
        return;
    }

    let signed_tx =
        Transaction::consensus_decode(&mut hex::decode(signed_tx_hex).unwrap().as_slice()).unwrap();

    match relayer.bitcoin_client.send_raw_transaction(&signed_tx) {
        Ok(txid) => {
            debug!("Cet sent to bitcoin: {}, cet type: {}", txid, cet_type);
        }
        Err(e) => {
            error!("Failed to send cet to bitcoin: {}", e);
        }
    }
}

pub async fn handle_redemption_tx(relayer: &Relayer, id: u64) {
    let redemption = match get_redemption(&relayer.config.side_chain.grpc, id).await {
        Ok(resp) => match resp.into_inner().redemption {
            Some(redemption) => redemption,
            None => {
                error!("No redemption exists on side, id: {}", id);
                return;
            }
        },
        Err(e) => {
            error!("Failed to query redemption, id: {}, err: {}", id, e);
            return;
        }
    };

    let signed_tx = match get_signed_tx_from_psbt(&redemption.tx) {
        Ok(signed_tx) => signed_tx,
        Err(e) => {
            error!(
                "Failed to extract signed redemption tx, id: {}, err: {}",
                id, e
            );
            return;
        }
    };

    match relayer.bitcoin_client.send_raw_transaction(&signed_tx) {
        Ok(txid) => {
            debug!("Redemption tx sent to bitcoin: {}", txid);
        }
        Err(e) => {
            error!("Failed to send redemption tx to bitcoin: {}", e);
        }
    }
}

pub async fn handle_liquidation_settlement_tx(relayer: &Relayer, liquidation_id: u64) {
    let liquidation = match get_liquidation(&relayer.config.side_chain.grpc, liquidation_id).await {
        Ok(resp) => match resp.into_inner().liquidation {
            Some(liquidation) => liquidation,
            None => {
                error!(
                    "No liquidation exists on side, liquidation id: {}",
                    liquidation_id
                );
                return;
            }
        },
        Err(e) => {
            error!(
                "Failed to query liquidation, liquidation id: {}, err: {}",
                liquidation_id, e
            );
            return;
        }
    };

    if liquidation.status != LiquidationStatus::Settled as i32 {
        error!(
            "Liquidation not settled yet, liquidation id: {}",
            liquidation_id
        );
        return;
    }

    let signed_settlement_tx = match get_signed_tx_from_psbt(&liquidation.settlement_tx) {
        Ok(signed_tx) => signed_tx,
        Err(e) => {
            error!(
                "Failed to extract signed settlement tx, liquidation id: {}, err: {}",
                liquidation_id, e
            );
            return;
        }
    };

    match relayer
        .bitcoin_client
        .send_raw_transaction(&signed_settlement_tx)
    {
        Ok(txid) => {
            debug!("Liquidation settlement tx sent to bitcoin: {}", txid);
        }
        Err(e) => {
            error!("Failed to send settlement tx to bitcoin: {}", e);
        }
    }
}

pub fn is_deposit_tx(relayer: &Relayer, tx: &Transaction, network: Network) -> bool {
    tx.output.iter().any(|out| {
        is_vault(
            relayer,
            bitcoin_utils::get_address_from_pk_script(out.clone().script_pubkey, network),
        )
    })
}

pub fn is_vault(relayer: &Relayer, address: String) -> bool {
    relayer
        .db_relayer
        .get(format!("{}:{}", DB_KEY_VAULT_PREFIX, address))
        .map_or(false, |v| v.is_some())
}

pub fn get_vault(relayer: &Relayer, tx: &Transaction, network: Network) -> String {
    for out in tx.output.iter() {
        let address = bitcoin_utils::get_address_from_pk_script(out.script_pubkey.clone(), network);
        if is_vault(relayer, address.clone()) {
            return address;
        }
    }

    return "".to_string();
}

pub(crate) fn get_last_scanned_height_bitcoin(relayer: &Relayer) -> u64 {
    match relayer.db_relayer.get(DB_KEY_BITCOIN_BLOCK_HEIGHT) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(relayer.config().last_scanned_height_bitcoin)
        }
        _ => relayer.config().last_scanned_height_bitcoin,
    }
}

fn save_last_scanned_height_bitcoin(relayer: &Relayer, height: u64) {
    let _ = relayer.db_relayer.insert(
        DB_KEY_BITCOIN_BLOCK_HEIGHT,
        serde_json::to_vec(&height).unwrap(),
    );
}

pub(crate) fn get_last_scanned_height_side(relayer: &Relayer) -> u64 {
    match relayer.db_relayer.get(DB_KEY_SIDE_BLOCK_HEIGHT) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(relayer.config().last_scanned_height_side)
        }
        _ => relayer.config().last_scanned_height_side,
    }
}

fn save_last_scanned_height_side(relayer: &Relayer, height: u64) {
    let _ = relayer.db_relayer.insert(
        DB_KEY_SIDE_BLOCK_HEIGHT,
        serde_json::to_vec(&height).unwrap(),
    );
}

fn save_vault(relayer: &Relayer, vault: String) {
    let _ = relayer
        .db_relayer
        .insert(format!("{}:{}", DB_KEY_VAULT_PREFIX, vault), vec![]);
}
