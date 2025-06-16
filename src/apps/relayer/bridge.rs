use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock,
};

use bitcoin::{consensus::encode, Address, Block, BlockHash, OutPoint, Psbt, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use tokio::join;
use tokio::time::{sleep, Duration};
use tonic::{Response, Status};
use tracing::{debug, error, info};

use cosmos_sdk_proto::{cosmos::tx::v1beta1::BroadcastTxResponse, Any};

use crate::{
    apps::relayer::Relayer,
    helper::{
        bitcoin::{self as bitcoin_utils},
        client_side::{self, send_cosmos_transaction},
        encoding::{from_base64, to_base64},
    },
};

use side_proto::side::btcbridge::{
    MsgSubmitDepositTransaction, MsgSubmitFeeRate, MsgSubmitWithdrawTransaction,
    SigningStatus,
};
use side_proto::{
    cosmos::base::query::v1beta1::PageRequest,
    side::btcbridge::{
        query_client::QueryClient as BridgeQueryClient, QuerySigningRequestRequest,
        QuerySigningRequestsRequest,
    },
};

const DB_KEY_BITCOIN_TIP: &str = "bitcoin_tip";
const DB_KEY_VAULTS: &str = "bitcoin_vaults";
const DB_KEY_VAULTS_LAST_UPDATE: &str = "bitcoin_vaults_last_update";

/// Start relayer tasks
/// 1. Scan vault txs
/// 2. Sync signed txs
/// 3. Submit fee rate
pub async fn start_relayer_tasks(relayer: &Relayer) {
    join!(
        scan_vault_txs(&relayer),
        sync_signed_transactions(&relayer),
        submit_fee_rate(&relayer),
    );
}

static SEQUENCE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

pub async fn sync_signed_transactions(relayer: &Relayer) {
    let host = relayer.config().side_chain.grpc.as_str();
    let interval = relayer.config().loop_interval;

    loop {
        let mut bridge_client = match BridgeQueryClient::connect(host.to_string()).await {
            Ok(client) => client,
            Err(e) => {
                error!("Error: {:?}", e);
                continue;
            }
        };

        if SEQUENCE.load(Ordering::Relaxed) == 0 {
            let x = bridge_client
                .query_signing_requests(QuerySigningRequestsRequest {
                    status: SigningStatus::Broadcasted as i32,
                    pagination: Some(PageRequest {
                        key: vec![],
                        offset: 0,
                        limit: 1,
                        count_total: false,
                        reverse: false,
                    }),
                })
                .await;

            let resp = match x {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    error!("Error: {:?}", e);
                    continue;
                }
            };

            println!("signed txs: {:?}", resp.requests.len());

            if resp.requests.len() > 0 {
                let s = resp.requests[0].sequence;
                if s >= 1 {
                    // latest sequence on chain
                    SEQUENCE.fetch_add(s, Ordering::Relaxed);
                }
            } else {
                sleep(Duration::from_secs(interval)).await;
                continue;
            }
        }

        loop {
            let sequence = SEQUENCE.load(Ordering::SeqCst);

            info!("Start syncing signed transaction {}", sequence);

            match bridge_client
                .query_signing_request(QuerySigningRequestRequest { sequence })
                .await
            {
                Ok(r) => {
                    if let Some(sr) = r.into_inner().request {
                        if sr.status == SigningStatus::Unspecified as i32 {
                            sleep(Duration::from_secs(interval)).await;
                            continue;
                        }
                        if sr.status == SigningStatus::Confirmed as i32
                            || sr.status == SigningStatus::Failed as i32
                        {
                            SEQUENCE.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }

                        if sr.status != SigningStatus::Broadcasted as i32 || sr.psbt.len() == 0 {
                            SEQUENCE.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }

                        let psbt_bytes = from_base64(&sr.psbt).unwrap();
                        let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
                            Ok(psbt) => psbt,
                            Err(e) => {
                                error!("Failed to deserialize PSBT: {}", e);
                                continue;
                            }
                        };

                        let signed_tx = psbt
                            .clone()
                            .extract_tx()
                            .expect("failed to extract signed tx");

                        match relayer.bitcoin_client.send_raw_transaction(&signed_tx) {
                            Ok(txid) => {
                                SEQUENCE.fetch_add(1, Ordering::SeqCst);

                                info!("PSBT broadcasted to Bitcoin: {}", txid);
                            }
                            Err(err) => {
                                error!(
                                    "Failed to broadcast PSBT: {:?}, err: {:?}",
                                    signed_tx.compute_txid(),
                                    err
                                );

                                if err
                                    .to_string()
                                    .contains("Transaction already in block chain")
                                {
                                    SEQUENCE.fetch_add(1, Ordering::SeqCst);
                                }

                                if err
                                    .to_string()
                                    .contains("Transaction outputs already in utxo set")
                                {
                                    SEQUENCE.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                }
            };

            continue;
        }
    }
}

pub async fn scan_vault_txs(relayer: &Relayer) {
    let interval = relayer.config().loop_interval;

    loop {
        let height = get_last_scanned_height(relayer) + 1;

        let side_tip =
            match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
                Ok(res) => res.get_ref().height,
                Err(e) => {
                    error!("Failed to get tip from side chain: {}", e);
                    continue;
                }
            };

        let confirmations =
            client_side::get_confirmation_depth(&relayer.config().side_chain.grpc).await;
        if height > side_tip - confirmations + 1 {
            debug!(
                "No new txs to sync, height: {}, side tip: {}, sleep for {} seconds...",
                height, side_tip, interval
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

        debug!("Scanning height: {:?}, side tip: {:?}", height, side_tip);
        if scan_vault_txs_by_height(relayer, height).await {
            save_last_scanned_height(relayer, height);
        }
    }
}

pub async fn scan_vault_txs_by_height(relayer: &Relayer, height: u64) -> bool {
    let block_hash = match relayer.bitcoin_client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to get block hash: {:?}, err: {:?}", height, e);
            return false;
        }
    };

    let block = match relayer.bitcoin_client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", height, e);
            return false;
        }
    };

    let vaults = match get_vaults(relayer).await {
        Ok(vaults) => {
            if vaults.is_empty() {
                debug!("no bridge vaults found");
                return true;
            }

            vaults
        }
        Err(e) => {
            error!("Failed to get bridge vaults, err: {}", e);
            return false;
        }
    };

    for (i, tx) in block.txdata.iter().enumerate() {
        debug!(
            "Checking tx {:?}, height: {:?}, index: {:?}",
            tx.compute_txid(),
            height,
            i
        );

        check_and_handle_tx_with_retry(relayer, &block_hash, &block, tx, i, &vaults).await;
    }

    return true;
}

pub async fn check_and_handle_tx_with_retry(
    relayer: &Relayer,
    block_hash: &BlockHash,
    block: &Block,
    tx: &Transaction,
    index: usize,
    vaults: &Vec<String>,
) {
    let mut attempts = 0;

    loop {
        if check_and_handle_tx(relayer, &block_hash, &block, tx, index, &vaults).await {
            return;
        }

        attempts += 1;
        if attempts >= relayer.config.max_attempts {
            return;
        }
    }
}

pub async fn check_and_handle_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    block: &Block,
    tx: &Transaction,
    index: usize,
    vaults: &Vec<String>,
) -> bool {
    if bitcoin_utils::may_be_withdraw_tx(&tx) {
        let prev_txid = tx.input[0].previous_output.txid;
        let prev_vout = tx.input[0].previous_output.vout;

        let address = match relayer.bitcoin_client.get_raw_transaction(&prev_txid, None) {
            Ok(prev_tx) => {
                if prev_tx.output.len() <= prev_vout as usize {
                    error!("Invalid previous tx");

                    // continue due to the tx is invalid
                    return true;
                }

                match Address::from_script(
                    prev_tx.output[prev_vout as usize].script_pubkey.as_script(),
                    relayer.config().bitcoin.network,
                ) {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        error!("Failed to parse public key script: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to get the previous tx: {:?}, err: {:?}",
                    prev_txid, e
                );

                None
            }
        };

        if address.is_some() {
            let address = address.unwrap().to_string();
            if vaults.contains(&address) {
                debug!("Withdrawal tx found... {:?}", &tx);

                let proof = bitcoin_utils::compute_tx_proof(
                    block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
                    index,
                );

                match send_withdraw_tx(relayer, &block_hash, &tx, proof).await {
                    Ok(resp) => {
                        let tx_response = resp.into_inner().tx_response.unwrap();
                        if tx_response.code != 0 {
                            error!("Failed to submit withdrawal tx: {:?}", tx_response);
                            return false;
                        }

                        info!("Submitted withdrawal tx: {:?}", tx_response);
                        return true;
                    }
                    Err(e) => {
                        error!("Failed to submit withdrawal tx: {:?}", e);
                        return false;
                    }
                }
            }
        }
    }

    if bitcoin_utils::is_deposit_tx(tx, relayer.config().bitcoin.network, &vaults) {
        debug!("Deposit tx found... {:?}", &tx);

        if bitcoin_utils::is_runes_deposit(tx) {
            if !relayer.config().relay_runes {
                debug!("Skip the tx due to runes relaying not enabled");
                return true;
            }

            let edict = match bitcoin_utils::parse_runes(tx) {
                Some(edict) => edict,
                None => {
                    debug!("Failed to parse runes deposit tx {}", tx.compute_txid());

                    // continue due to the deposit is invalid
                    return true;
                }
            };

            // get the rune by id
            let rune = match relayer.ordinals_client.get_rune(edict.id).await {
                Ok(rune) => rune.entry.spaced_rune,
                Err(e) => {
                    error!("Failed to get rune {}: {}", edict.id, e);

                    // continue due to the deposit may be invalid
                    // or this can be correctly handled for other relayers
                    return true;
                }
            };

            // get the runes output
            let output = match relayer
                .ordinals_client
                .get_output(OutPoint::new(tx.compute_txid(), edict.output))
                .await
            {
                Ok(output) => output,
                Err(e) => {
                    error!(
                        "Failed to get output {}:{} from ord: {}",
                        tx.compute_txid(),
                        edict.output,
                        e
                    );

                    // continue due to the deposit may be invalid
                    // or this can be correctly handled for other relayers
                    return true;
                }
            };

            // validate if the runes deposit is valid
            if !bitcoin_utils::validate_runes(&edict, &rune, &output) {
                debug!("Failed to validate runes deposit tx {}", tx.compute_txid());

                // continue due to the deposit is invalid
                return true;
            }
        }

        let proof = bitcoin_utils::compute_tx_proof(
            block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
            index,
        );
        let prev_txid = tx.input[0].previous_output.txid;
        let prev_tx = match relayer.bitcoin_client.get_raw_transaction(&prev_txid, None) {
            Ok(prev_tx) => prev_tx,
            Err(e) => {
                error!(
                    "Failed to get the previous tx: {:?}, err: {:?}",
                    prev_txid, e
                );

                return false;
            }
        };

        match send_deposit_tx(relayer, &block_hash, &prev_tx, &tx, proof).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to submit deposit tx: {:?}", tx_response);
                    return false;
                }

                info!("Submitted deposit tx: {:?}", tx_response);
                return true;
            }
            Err(e) => {
                error!("Failed to submit deposit tx: {:?}", e);
                return false;
            }
        }
    }

    return true;
}

pub async fn check_and_handle_tx_by_hash(relayer: &Relayer, hash: &Txid) {
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

    let vaults = match get_vaults(relayer).await {
        Ok(vaults) => {
            if vaults.is_empty() {
                error!("no bridge vaults found");
                return;
            }

            vaults
        }
        Err(e) => {
            error!("Failed to get bridge vaults, err: {}", e);
            return;
        }
    };

    check_and_handle_tx(relayer, &block_hash, &block, &tx, tx_index, &vaults).await;
}

pub async fn send_withdraw_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitWithdrawTransaction {
        sender: relayer.config().relayer_bitcoin_address().to_string(),
        blockhash: block_hash.to_string(),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting withdrawal tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(&relayer.identifier, relayer.config(), any_msg).await
}

pub async fn send_deposit_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    prev_tx: &Transaction,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitDepositTransaction {
        sender: relayer.config().relayer_bitcoin_address(),
        blockhash: block_hash.to_string(),
        prev_tx_bytes: to_base64(encode::serialize(prev_tx).as_slice()),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting deposit tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(&relayer.identifier, &relayer.config(), any_msg).await
}

pub(crate) fn get_last_scanned_height(relayer: &Relayer) -> u64 {
    match relayer.db_relayer.get(DB_KEY_BITCOIN_TIP) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(relayer.config().last_scanned_height_bitcoin)
        }
        _ => relayer.config().last_scanned_height_bitcoin,
    }
}

fn save_last_scanned_height(relayer: &Relayer, height: u64) {
    let _ = relayer
        .db_relayer
        .insert(DB_KEY_BITCOIN_TIP, serde_json::to_vec(&height).unwrap());
}

async fn get_vaults(relayer: &Relayer) -> anyhow::Result<Vec<String>> {
    if let Ok(Some(last_update)) = relayer.db_relayer.get(DB_KEY_VAULTS_LAST_UPDATE) {
        let last_update: u64 = serde_json::from_slice(&last_update).unwrap_or(0);
        let now = chrono::Utc::now().timestamp() as u64;
        if now - last_update < 60 * 60 * 24 {
            // 24 hours
            if let Ok(Some(vaults)) = relayer.db_relayer.get(DB_KEY_VAULTS) {
                return Ok(serde_json::from_slice(&vaults).unwrap_or(vec![]));
            };
        }
    }

    match client_side::get_bridge_vaults(&relayer.config().side_chain.grpc).await {
        Ok(vaults) => {
            if !vaults.is_empty() {
                let _ = relayer
                    .db_relayer
                    .insert(DB_KEY_VAULTS, serde_json::to_vec(&vaults).unwrap());

                let _ = relayer.db_relayer.insert(
                    DB_KEY_VAULTS_LAST_UPDATE,
                    serde_json::to_vec(&chrono::Utc::now().timestamp()).unwrap(),
                );
            }

            Ok(vaults)
        }
        Err(e) => Err(e),
    }
}

pub async fn submit_fee_rate(relayer: &Relayer) {
    let submit_fee_rate = relayer.config().fee_provider.submit_fee_rate;
    if !submit_fee_rate {
        return;
    }

    let interval = relayer.config().loop_interval;

    loop {
        match relayer.fee_provider_client.get_fees().await {
            Ok(bitcoin_fees) => {
                let fee_rate = bitcoin_fees.fastest_fee;
                submit_fee_rate_to_side(relayer, fee_rate).await;
            }
            Err(e) => {
                error!("Failed to get fee rates: {}", e);
            }
        };

        sleep(Duration::from_secs(interval)).await;
    }
}

pub async fn submit_fee_rate_to_side(relayer: &Relayer, fee_rate: i64) {
    let msg_submit_fee_rate = MsgSubmitFeeRate {
        sender: relayer.config().relayer_bitcoin_address().to_string(),
        fee_rate,
    };

    info!("Submitting fee rate: {:?}", msg_submit_fee_rate);
    let any_msg = Any::from_msg(&msg_submit_fee_rate).unwrap();
    match send_cosmos_transaction(&relayer.identifier, relayer.config(), any_msg).await {
        Ok(resp) => {
            let tx_response = resp.into_inner().tx_response.unwrap();
            if tx_response.code != 0 {
                error!("Failed to submit fee rate: {:?}", tx_response);
                return;
            }
            info!("Success to submit fee rate: {:?}", tx_response);
        }
        Err(e) => {
            error!("Failed to submit fee rate: {:?}", e);
        }
    }
}
