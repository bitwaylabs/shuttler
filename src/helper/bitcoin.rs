
use anyhow::anyhow;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::Psbt;
use bitcoin::{hashes::Hash,
    consensus::encode::serialize, key::Secp256k1, opcodes, Address, Network, PublicKey, ScriptBuf, TapNodeHash, TapSighashType, Transaction, Txid, XOnlyPublicKey
};
use bitcoin::{consensus::encode::deserialize, Transaction as TransactionV30};
use frost_adaptor_signature::{keys::PublicKeyPackage, VerifyingKey};
use ordinals::SpacedRune;
use tracing::info;

use crate::apps::{Context, Input, SignMode, Task};
use crate::helper::encoding::from_base64;
use crate::helper::mem_store;
use crate::helper::store::Store;

use super::merkle_proof;

// Magic txin sequence for withdrawal txs
const MAGIC_SEQUENCE: u32 = (1 << 31) + 0xde;

pub fn new_task_from_psbt(ctx: &Context, psbt_base64: &String, sign_mode: SignMode) -> anyhow::Result<Task> {

    let psbt_bytes = from_base64(&psbt_base64)?;

    let psbt = Psbt::deserialize(psbt_bytes.as_slice())?;
    let task_id = &psbt.unsigned_tx.compute_txid().to_string();

    info!("Prepare for signing: {:?} {} inputs ", &task_id[..6], psbt.inputs.len()  );
    let mut inputs = vec![];
    let preouts = psbt.inputs.iter()
        //.filter(|input| input.witness_utxo.is_some())
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();

    for (i, input) in psbt.inputs.iter().enumerate() {

        let script = input.witness_utxo.clone().unwrap().script_pubkey;
        let address = Address::from_script(&script, ctx.conf.bitcoin.network)?.to_string();

        // check if there are sufficient participants for this tasks
        let participants = mem_store::count_task_participants(ctx, &address.to_string());
        match ctx.keystore.get(&address) {
            Some(k) => if participants.len() < k.priv_key.min_signers().clone() as usize { return Err(anyhow!("insufficient signers")); },
            None => continue,
        };

        // get the message to sign
        let hash_ty = input
            .sighash_type
            .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
            .unwrap_or(TapSighashType::Default);
        let hash = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash( i,&Prevouts::All(&preouts),hash_ty,)?;

        let input = Input {
            key: address,
            index: i,
            participants,
            message: hash.to_raw_hash().to_byte_array().to_vec(),
            mode: sign_mode.clone(),
            signature: None,
        };

        inputs.push(input);
 
    };

    if inputs.len() == 0 {
        return Err(anyhow!("invalid psbt, 0 input"));
    }

    Ok(Task::new_signing(task_id.to_owned(), psbt_base64.clone(), inputs))
}

pub fn schnorr_signature_from_frost(frost_signature: frost_adaptor_signature::Signature) -> bitcoin::secp256k1::schnorr::Signature {
    let sig_bytes = frost_signature.serialize().unwrap();
    bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap()
}

pub fn taproot_signature_from_frost(frost_signature: frost_adaptor_signature::Signature) -> bitcoin::taproot::Signature {
    bitcoin::taproot::Signature {
        signature: schnorr_signature_from_frost(frost_signature),
        sighash_type: TapSighashType::Default
    }
}

pub fn convert_tweak(tweak: &Option<TapNodeHash>) -> Option<&[u8]> {
    match tweak {
        Some(tnh) => Some(tnh.as_byte_array()),
        None => None,
    }
}

pub fn generate_tweak(pubkey: &PublicKeyPackage, index: u16) -> Option<TapNodeHash> {
    let key_bytes = match pubkey.verifying_key().serialize() {
        Ok(b) => b,
        Err(_) => return None,
    };
    let x_only_pubkey = XOnlyPublicKey::from_slice(&key_bytes[1..]).unwrap();

    let mut script = bitcoin::ScriptBuf::new();
    script.push_slice(x_only_pubkey.serialize());
    script.push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
    script.push_slice((index as u8).to_be_bytes());

    Some(TapNodeHash::from_script(
        script.as_script(),
        bitcoin::taproot::LeafVersion::TapScript,
    ))
}

pub fn get_group_address(verify_key: &VerifyingKey, network: Network) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let key_bytes = verify_key.serialize().unwrap();
    let pubk = PublicKey::from_slice(&key_bytes ).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();
    Address::p2tr(&secp, internal_key, None, network)
}

pub fn get_group_address_by_tweak(
    verify_key: &VerifyingKey,
    tweak: Option<TapNodeHash>,
    network: Network,
) -> Address {    
    let key_bytes = verify_key.serialize().unwrap();
    let pubk = PublicKey::from_slice(&key_bytes ).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();

    Address::p2tr(&secp, internal_key, tweak, network)
}

pub fn get_address_from_pk_script(pk_script: ScriptBuf, network: Network) -> String {
    match Address::from_script(&pk_script, network) {
        Ok(address) => address.to_string(),
        _ => String::new(),
    }
}

pub fn get_signed_tx_from_psbt(psbt_base64: &String) -> anyhow::Result<Transaction> {
    let psbt_bytes = from_base64(&psbt_base64)?;

    let psbt = Psbt::deserialize(psbt_bytes.as_slice())?;

    let signed_tx = psbt.extract_tx()?;

    Ok(signed_tx)
}

pub fn compute_tx_proof(txids: Vec<Txid>, index: usize) -> Vec<String> {
    merkle_proof::compute_tx_proof(txids, index)
}

/// Check if the transaction is a deposit transaction
/// A deposit transaction is a transaction that has a vault address as one of its output
/// the vault address should be fetched from side chain. so none signer can also run a relayer
pub fn is_deposit_tx(tx: &Transaction, network: Network, vaults: &Vec<String>) -> bool {
    tx.output.iter().any(|out| {
        vaults.contains(&get_address_from_pk_script(
            out.clone().script_pubkey,
            network,
        ))
    })
}

// Check if the given tx may be a withdrawal tx by sequence
pub fn may_be_withdraw_tx(tx: &Transaction) -> bool {
    if tx.input.len() < 1 {
        return false;
    }

    tx.input[0].sequence.0 == MAGIC_SEQUENCE
}


// Check if the given deposit tx is for runes
pub fn is_runes_deposit(tx: &Transaction, network: Network, runes_vault: String) -> bool {
    let runes_identifier = vec![
        opcodes::all::OP_RETURN.to_u8(),
        opcodes::all::OP_PUSHNUM_13.to_u8(),
    ];

    if !tx
        .output
        .iter()
        .any(|out| out.script_pubkey.as_bytes().starts_with(&runes_identifier))
    {
        return false;
    }

    is_deposit_tx(tx, network, &vec![runes_vault])
}

// Parse runes from the given tx
// Only an edict operation is allowed
pub fn parse_runes(tx: &Transaction) -> Option<ordinals::Edict> {
    match ordinals::Runestone::decipher(&to_transaction_v30(&tx)) {
        Some(artifact) => match artifact {
            ordinals::Artifact::Runestone(runestone) => {
                if runestone.etching.is_some()
                    || runestone.mint.is_some()
                    || runestone.edicts.len() != 1
                    || runestone.edicts[0].output >= tx.output.len() as u32
                {
                    return None;
                }

                return Some(runestone.edicts[0]);
            }
            _ => None,
        },
        None => None,
    }
}

// Validate runes against the output of the ord indexer
pub fn validate_runes(
    edict: &ordinals::Edict,
    rune: &SpacedRune,
    runes_output: &ord::api::Output,
    runes_vault: String,
) -> bool {
    match &runes_output.address {
        Some(addr) => {
            if addr.clone().assume_checked().to_string() != runes_vault {
                return false;
            }
        }
        None => return false,
    };

    runes_output
        .runes
        .as_ref()
        .and_then(|runes| runes.get(rune))
        .map_or(false, |r| r.amount >= edict.amount)
}

// Convert the given transaction to the v30 version
// Make sure that the tx is valid
fn to_transaction_v30(tx: &Transaction) -> TransactionV30 {
    let serialized_tx = serialize(tx);
    deserialize(&serialized_tx).unwrap()
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash as _, opcodes, transaction::Version, Amount, OutPoint, Sequence, TxIn, TxOut};

    use crate::helper::encoding::from_base64;

    use super::*;

    #[test]
    fn test_withdraw_tx_check() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: [TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                sequence: Sequence(MAGIC_SEQUENCE),
                ..Default::default()
            }]
            .to_vec(),
            output: [TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::builder()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
            }]
            .to_vec(),
        };

        assert!(may_be_withdraw_tx(&tx), "may be a withdrawal tx")
    }

    #[test]
    fn test_tx_proof() {
        // mainnet block: 80000
        let mut txid1 =
            hex::decode("c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25")
                .unwrap();
        let mut txid2 =
            hex::decode("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2")
                .unwrap();

        txid1.reverse();
        txid2.reverse();

        let txids = vec![
            Txid::from_slice(txid1.as_slice()).unwrap(),
            Txid::from_slice(txid2.as_slice()).unwrap(),
        ];

        let proof = compute_tx_proof(txids, 1);
        assert_eq!(proof.len(), 1);

        let mut branch = from_base64(&proof[0]).unwrap();
        branch[1..].reverse();
        assert_eq!(
            hex::encode(branch),
            "01c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25"
        );
    }
}
