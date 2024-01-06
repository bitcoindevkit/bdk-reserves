// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof of reserves
//!
//! This module provides the ability to create proofs of reserves.
//! A proof is a valid but unspendable transaction. By signing a transaction
//! that spends some UTXOs we are proofing that we have control over these funds.
//! The implementation is inspired by the following BIPs:
//! https://github.com/bitcoin/bips/blob/master/bip-0127.mediawiki
//! https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki

use bdk::bitcoin::blockdata::opcodes;
use bdk::bitcoin::blockdata::script::{Builder, Script};
use bdk::bitcoin::blockdata::transaction::{EcdsaSighashType, OutPoint, TxIn, TxOut};
use bdk::bitcoin::consensus::encode::serialize;
use bdk::bitcoin::hash_types::{PubkeyHash, Txid};
use bdk::bitcoin::hashes::{hash160, sha256, Hash};
use bdk::bitcoin::util::psbt::{raw::Key, Input, PartiallySignedTransaction as PSBT};
use bdk::bitcoin::{Sequence, Transaction};
use bdk::database::BatchDatabase;
use bdk::wallet::tx_builder::TxOrdering;
use bdk::wallet::Wallet;
use bdk::Error;

use std::collections::BTreeMap;

pub use crate::txout_set::{TxOutSet, WalletAtHeight};

pub const PSBT_IN_POR_COMMITMENT: u8 = 0x09;

/// The API for proof of reserves
pub trait ProofOfReserves {
    /// Create a proof for all spendable UTXOs in a wallet
    fn create_proof(&self, message: &str) -> Result<PSBT, ProofError>;

    /// Make sure this is a proof, and not a spendable transaction.
    /// Make sure the proof is valid.
    /// Currently proofs can only be validated against the tip of the chain.
    /// If some of the UTXOs in the proof were spent in the meantime, the proof will fail.
    /// We can currently not validate whether it was valid at a certain block height.
    /// With the max_block_height parameter the caller can ensure that only UTXOs with sufficient confirmations are considered.
    /// If no max_block_height is provided, also UTXOs from transactions in the mempool are considered.
    /// Returns the spendable amount of the proof.
    fn verify_proof(
        &self,
        psbt: &PSBT,
        message: &str,
        max_block_height: Option<u32>,
    ) -> Result<u64, ProofError>;
}

/// Proof error
#[derive(Debug)]
pub enum ProofError {
    /// Less than two inputs
    WrongNumberOfInputs,
    /// Must have exactly 1 output
    WrongNumberOfOutputs,
    /// Challenge input does not match
    ChallengeInputMismatch,
    /// Found an input that has no signature at position
    NotSignedInput(usize),
    /// Found an input with an unsupported SIGHASH type at position
    UnsupportedSighashType(usize),
    /// Signature validation failed
    SignatureValidation(usize, String),
    /// The output is not valid
    InvalidOutput,
    /// Input and output values are not equal, implying a miner fee
    InAndOutValueNotEqual,
    /// No matching outpoint found
    OutpointNotFound(usize),
    /// Error looking up outpoint other than if outpoint doesn't exist, or outpoint is already spent
    OutpointLookupError,
    /// A wrapped BDK Error
    BdkError(Error),
}

impl From<bdk::Error> for ProofError {
    fn from(error: bdk::Error) -> Self {
        ProofError::BdkError(error)
    }
}

impl From<ProofError> for bdk::Error {
    fn from(error: ProofError) -> Self {
        if let ProofError::BdkError(err) = error {
            err
        } else {
            bdk::Error::Generic(format!("{:?}", error))
        }
    }
}

impl<D> ProofOfReserves for Wallet<D>
where
    D: BatchDatabase,
{
    fn create_proof(&self, message: &str) -> Result<PSBT, ProofError> {
        if message.is_empty() {
            return Err(ProofError::ChallengeInputMismatch);
        }
        let challenge_txin = challenge_txin(message);

        let challenge_key = Key {
            type_value: PSBT_IN_POR_COMMITMENT,
            key: Vec::new(),
        };

        let mut unknown_psbt_keys: BTreeMap<Key, Vec<u8>> = BTreeMap::new();
        unknown_psbt_keys.insert(challenge_key, message.as_bytes().into());

        let challenge_psbt_inp = Input {
            witness_utxo: Some(TxOut {
                value: 0,
                script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
            }),
            final_script_sig: Some(Script::default()), /* "finalize" the input with an empty scriptSig */
            unknown: unknown_psbt_keys,
            ..Default::default()
        };

        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = Script::new_p2pkh(&pkh);

        let mut builder = self.build_tx();
        builder
            .drain_wallet()
            .add_foreign_utxo(challenge_txin.previous_output, challenge_psbt_inp, 42)?
            .fee_absolute(0)
            .only_witness_utxo()
            .current_height(0)
            .drain_to(out_script_unspendable)
            .ordering(TxOrdering::Untouched);
        let (psbt, _details) = builder.finish().map_err(ProofError::BdkError)?;

        Ok(psbt)
    }

    fn verify_proof(
        &self,
        psbt: &PSBT,
        message: &str,
        max_block_height: Option<u32>,
    ) -> Result<u64, ProofError> {
        if let Some(max_block_height) = max_block_height {
            let txouts = WalletAtHeight::new(self, max_block_height);

            psbt.verify_reserve_proof(message, txouts)
        } else {
            psbt.verify_reserve_proof(message, self)
        }
    }
}

/// Trait for Transaction-centric proofs
pub trait ReserveProof {
    /// Verify a proof transaction.
    /// Look up utxos with get_prevout()
    fn verify_reserve_proof<T: TxOutSet>(&self, message: &str, txouts: T) -> Result<u64, ProofError>;

    /// Verify that this transaction correctly includes the challenge
    fn verify_challenge(&self, message: &str) -> Result<(), ProofError>;
}

impl ReserveProof for Transaction {
    fn verify_reserve_proof<T: TxOutSet>(&self, message: &str, txouts: T) -> Result<u64, ProofError>
    {
        if self.output.len() != 1 {
            return Err(ProofError::WrongNumberOfOutputs);
        }
        if self.input.len() <= 1 {
            return Err(ProofError::WrongNumberOfInputs);
        }

        // verify the unspendable output
        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = Script::new_p2pkh(&pkh);

        if self.output[0].script_pubkey != out_script_unspendable {
            return Err(ProofError::InvalidOutput);
        }

        self.verify_challenge(message)?;

        let outpoint_iter = self.input
            .iter()
            .map(|txin| &txin.previous_output);

        // Try to look up outpoints
        let prevouts: Vec<Option<TxOut>> = txouts
            .get_prevouts(outpoint_iter)
            .map_err(|_| ProofError::OutpointLookupError)?;

        // Convert missing outpoints into errors
        let prevouts: Vec<(usize, TxOut)> = prevouts
            .into_iter()
            .enumerate()
            .skip(1)
            .map(|(i, txout)| match txout {
                Some(txout) => {
                    Ok((i, txout))
                },
                None => {
                    Err(ProofError::OutpointNotFound(i))
                },
            })
            .collect::<Result<_, _>>()?;

        let sum: u64 = prevouts.iter()
            .map(|(_i, prevout)| prevout.value)
            .sum();

        // inflow and outflow being equal means no miner fee
        if self.output[0].value != sum {
            return Err(ProofError::InAndOutValueNotEqual);
        }

        let serialized_tx = serialize(&self);

        // Check that all inputs besides the challenge input are valid
        prevouts
            .iter()
            .map(|(i, prevout)|
                bitcoinconsensus::verify(
                    prevout.script_pubkey.to_bytes().as_slice(),
                    prevout.value,
                    &serialized_tx,
                    *i,
                )
                .map_err(|e|
                    ProofError::SignatureValidation(*i, format!("{:?}", e))
                ),
            )
            .collect::<Result<(), _>>()?;

        // Check that all inputs besides the challenge input actually
        // commit to the challenge input by modifying the challenge
        // input and verifying that validation *fails*.
        //
        // If validation succeeds here, that input did not correctly
        // commit to the challenge input.
        let serialized_malleated_tx = {
            let mut malleated_tx = self.clone();

            let mut malleated_message = "MALLEATED: ".to_string();
            malleated_message.push_str(message);

            malleated_tx.input[0] = challenge_txin(&malleated_message);

            serialize(&malleated_tx)
        };

        prevouts
            .iter()
            .map(|(i, prevout)|
                match bitcoinconsensus::verify(
                    prevout.script_pubkey.to_bytes().as_slice(),
                    prevout.value,
                    &serialized_malleated_tx,
                    *i,
                ) {
                    Ok(_) => {
                        Err(ProofError::SignatureValidation(*i, "Does not commit to challenge input".to_string()))
                    },
                    Err(_) => {
                        Ok(())
                    }
                }
            )
            .collect::<Result<(), _>>()?;

        Ok(sum)
    }

    fn verify_challenge(&self, message: &str) -> Result<(), ProofError> {
        let challenge_txin = challenge_txin(message);

        if self.input[0].previous_output != challenge_txin.previous_output {
            return Err(ProofError::ChallengeInputMismatch);
        }

        Ok(())
    }
}

impl ReserveProof for PSBT {
    /// Make sure this is a proof, and not a spendable transaction.
    /// Make sure the proof is valid.
    /// Currently proofs can only be validated against the tip of the chain.
    /// If some of the UTXOs in the proof were spent in the meantime, the proof will fail.
    /// We can currently not validate whether it was valid at a certain block height.
    /// Since the caller provides the outpoints, he is also responsible to make sure they have enough confirmations.
    /// Returns the spendable amount of the proof.
    fn verify_reserve_proof<T: TxOutSet>(&self, message: &str, txouts: T) -> Result<u64, ProofError> {
        let tx = self.clone().extract_tx();

        // Redundant check to tx.verify_reserve_proof() to ensure error priority is not changed
        if tx.output.len() != 1 {
            return Err(ProofError::WrongNumberOfOutputs);
        }

        // verify that the inputs are signed, except the challenge
        if let Some((i, _inp)) = self
            .inputs
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_i, inp)| inp.final_script_sig.is_none() && inp.final_script_witness.is_none())
        {
            return Err(ProofError::NotSignedInput(i));
        }

        // Verify the SIGHASH
        if let Some((i, _psbt_in)) = self.inputs.iter().enumerate().find(|(_i, psbt_in)| {
            psbt_in.sighash_type.is_some() && psbt_in.sighash_type != Some(EcdsaSighashType::All.into())
        }) {
            return Err(ProofError::UnsupportedSighashType(i));
        }

        tx.verify_reserve_proof(message, txouts)
    }

    fn verify_challenge(&self, message: &str) -> Result<(), ProofError> {
        let tx = self.clone().extract_tx();

        tx.verify_challenge(message)
    }
}

/// Construct a challenge input with the message
fn challenge_txin(message: &str) -> TxIn {
    let message = "Proof-of-Reserves: ".to_string() + message;
    let message = sha256::Hash::hash(message.as_bytes());
    let txid = Txid::from_inner(message.into_inner());
    TxIn {
        previous_output: OutPoint::new(txid, 0),
        sequence: Sequence(0xFFFFFFFF),
        ..Default::default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk::SignOptions;
    use bdk::bitcoin::consensus::encode::serialize_hex;
    use bdk::bitcoin::consensus::encode::deserialize;
    use bdk::bitcoin::secp256k1::Secp256k1;
    use bdk::bitcoin::secp256k1::ecdsa::{SerializedSignature, Signature};
    use bdk::bitcoin::{EcdsaSighashType, Transaction, Witness};
    use bdk::wallet::get_funded_wallet;
    use std::str::FromStr;

    #[test]
    fn test_proof() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let psbt = wallet.create_proof(message).unwrap();

        let psbt_b64 = psbt.to_string();

        let expected = r#"cHNidP8BAH4BAAAAAnazTpCbEI8dIHmilAK8aXK6Zj3nPcEy5vZzHMw/SzoyAAAAAAD/////2johM0znoXIXT1lg+ySrvGrtq1IGXPJzpfi/emkV9iIAAAAAAP////8BUMMAAAAAAAAZdqkUn3/QltN+0sDj9/DPySS+70/862iIrAAAAAAAAQEKAAAAAAAAAAABUQEHAAEJE1RoaXMgYmVsb25ncyB0byBtZS4AAQEfUMMAAAAAAAAWABTs5SZXEFPahkVMngZneer50VAuaiIGAysFWAeL7DhpSoSTPWWTA+JXXa5+kWhZEUVBFb/WRIfjBOzlJlcAAA=="#;

        assert_eq!(psbt_b64, expected);
    }

    #[test]
    #[should_panic(
        expected = "Descriptor(Miniscript(Unexpected(\"unexpected «Key too short (<66 char), doesn't match any format»\")))"
    )]
    fn invalid_descriptor() {
        let descriptor = "wpkh(cVpPVqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let _psbt = wallet.create_proof(message).unwrap();
    }

    #[test]
    #[should_panic(expected = "ChallengeInputMismatch")]
    fn empty_message() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "";
        let _psbt = wallet.create_proof(message).unwrap();
    }

    fn get_signed_proof() -> PSBT {
        let psbt = "cHNidP8BAH4BAAAAAnazTpCbEI8dIHmilAK8aXK6Zj3nPcEy5vZzHMw/SzoyAAAAAAD/////2johM0znoXIXT1lg+ySrvGrtq1IGXPJzpfi/emkV9iIAAAAAAP////8BUMMAAAAAAAAZdqkUn3/QltN+0sDj9/DPySS+70/862iIrAAAAAAAAQEKAAAAAAAAAAABUQEHAAEJE1RoaXMgYmVsb25ncyB0byBtZS4AAQEfUMMAAAAAAAAWABTs5SZXEFPahkVMngZneer50VAuaiIGAysFWAeL7DhpSoSTPWWTA+JXXa5+kWhZEUVBFb/WRIfjBOzlJlcBBwABCGsCRzBEAiBfpF8pM16CA1zJLkvl2gZ5ziGHadpZt1/yWyiQ2dB8nwIgSdBcayBSRhQvvjZEEyGyaDSBWJOiPU+ww6KHAPKeB/wBIQMrBVgHi+w4aUqEkz1lkwPiV12ufpFoWRFFQRW/1kSH4wAA";
        PSBT::from_str(psbt).unwrap()
    }

    fn get_signed_proof_tx() -> Transaction {
        let psbt = get_signed_proof();
        psbt.extract_tx()
    }

    #[test]
    fn verify_internal() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let spendable = wallet.verify_proof(&psbt, message, None).unwrap();
        assert_eq!(spendable, 50_000);

        let tx = psbt.extract_tx();

        let spendable = tx.verify_reserve_proof(message, &wallet).unwrap();
        assert_eq!(spendable, 50_000);
    }

    #[test]
    #[should_panic(expected = "OutpointNotFound")]
    fn verify_internal_90() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let spendable = wallet.verify_proof(&psbt, message, Some(90)).unwrap();
        assert_eq!(spendable, 50_000);
    }

    #[test]
    #[should_panic(expected = "OutpointNotFound")]
    fn verify_internal_90_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let tx = get_signed_proof_tx();

        let spendable = tx.verify_reserve_proof(message, WalletAtHeight::new(&wallet, 90)).unwrap();

        assert_eq!(spendable, 50_000);
    }

    #[test]
    fn verify_internal_100() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let spendable = wallet.verify_proof(&psbt, message, Some(100)).unwrap();
        assert_eq!(spendable, 50_000);

        let tx = psbt.extract_tx();
        let spendable = tx.verify_reserve_proof(message, WalletAtHeight::new(&wallet, 100)).unwrap();

        assert_eq!(spendable, 50_000);
    }

    #[test]
    fn verify_external() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let unspents = wallet.list_unspent().unwrap();
        let outpoints: BTreeMap<OutPoint, TxOut> = unspents
            .iter()
            .map(|utxo| (utxo.outpoint, utxo.txout.clone()))
            .collect();

        let spendable = psbt.verify_reserve_proof(message, &outpoints).unwrap();
        assert_eq!(spendable, 50_000);

        let tx = psbt.extract_tx();

        let spendable = tx.verify_reserve_proof(message, &outpoints).unwrap();

        assert_eq!(spendable, 50_000);
    }

    #[test]
    #[should_panic(expected = "ChallengeInputMismatch")]
    fn wrong_message() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "Wrong message!";
        let psbt = get_signed_proof();
        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "ChallengeInputMismatch")]
    fn wrong_message_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "Wrong message!";
        let tx = get_signed_proof_tx();
        tx.verify_reserve_proof(message, &wallet).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongNumberOfInputs")]
    fn too_few_inputs() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.input.truncate(1);
        psbt.inputs.truncate(1);

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongNumberOfInputs")]
    fn too_few_inputs_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.input.truncate(1);
        psbt.inputs.truncate(1);

        let tx = psbt.extract_tx();

        tx.verify_reserve_proof(message, &wallet).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongNumberOfOutputs")]
    fn no_output() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.output.clear();
        psbt.inputs.clear();

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongNumberOfOutputs")]
    fn no_output_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.output.clear();
        psbt.inputs.clear();

        let tx = psbt.extract_tx();

        tx.verify_reserve_proof(message, &wallet).unwrap();
    }

    #[test]
    #[should_panic(expected = "NotSignedInput")]
    fn missing_signature() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].final_script_sig = None;
        psbt.inputs[1].final_script_witness = None;

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "SignatureValidation")]
    fn missing_signature_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].final_script_sig = None;
        psbt.inputs[1].final_script_witness = None;

        let tx = psbt.extract_tx();

        tx.verify_reserve_proof(message, &wallet).unwrap();
    }

    #[test]
    #[should_panic(expected = "SignatureValidation")]
    fn invalid_signature() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].final_script_sig = None;

        let invalid_signature = Signature::from_str("3045022100f3b7b0b1400287766edfe8ba66bc0412984cdb97da6bb4092d5dc63a84e1da6f02204da10796361dbeaeead8f68a23157dffa23b356ec14ec2c0c384ad68d582bb14").unwrap();
        let invalid_signature = SerializedSignature::from_signature(&invalid_signature);

        let mut invalid_witness = Witness::new();
        invalid_witness.push_bitcoin_signature(&invalid_signature, EcdsaSighashType::All);

        psbt.inputs[1].final_script_witness = Some(invalid_witness);

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "SignatureValidation")]
    fn invalid_signature_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].final_script_sig = None;

        let invalid_signature = Signature::from_str("3045022100f3b7b0b1400287766edfe8ba66bc0412984cdb97da6bb4092d5dc63a84e1da6f02204da10796361dbeaeead8f68a23157dffa23b356ec14ec2c0c384ad68d582bb14").unwrap();
        let invalid_signature = SerializedSignature::from_signature(&invalid_signature);

        let mut invalid_witness = Witness::new();
        invalid_witness.push_bitcoin_signature(&invalid_signature, EcdsaSighashType::All);

        psbt.inputs[1].final_script_witness = Some(invalid_witness);

        let tx = psbt.extract_tx();

        tx.verify_reserve_proof(message, &wallet).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedSighashType(1)")]
    fn wrong_sighash_type() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].sighash_type = Some(EcdsaSighashType::SinglePlusAnyoneCanPay.into());

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidOutput")]
    fn invalid_output() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();

        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0, 1, 2, 3]));
        let out_script_unspendable = Script::new_p2pkh(&pkh);
        psbt.unsigned_tx.output[0].script_pubkey = out_script_unspendable;

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidOutput")]
    fn invalid_output_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();

        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0, 1, 2, 3]));
        let out_script_unspendable = Script::new_p2pkh(&pkh);
        psbt.unsigned_tx.output[0].script_pubkey = out_script_unspendable;

        let tx = psbt.extract_tx();

        tx.verify_reserve_proof(message, &wallet).unwrap();
    }

    #[test]
    #[should_panic(expected = "InAndOutValueNotEqual")]
    fn sum_mismatch() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.output[0].value = 123;

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "InAndOutValueNotEqual")]
    fn sum_mismatch_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.output[0].value = 123;

        let tx = psbt.extract_tx();

        tx.verify_reserve_proof(message, &wallet).unwrap();
    }

    fn tx_from_hex(s: &str) -> Transaction {
        use bdk::bitcoin::hashes::hex::FromHex;
        let tx = <Vec<u8> as FromHex>::from_hex(s).unwrap();

        deserialize(&mut tx.as_slice()).unwrap()
    }

    #[test]
    fn test_signed_tx() {
        let tx = tx_from_hex("0100000000010276b34e909b108f1d2079a29402bc6972ba663de73dc132e6f6731ccc3f4b3a320000000000ffffffffda3a21334ce7a172174f5960fb24abbc6aedab52065cf273a5f8bf7a6915f6220000000000ffffffff0150c30000000000001976a9149f7fd096d37ed2c0e3f7f0cfc924beef4ffceb6888ac000247304402205fa45f29335e82035cc92e4be5da0679ce218769da59b75ff25b2890d9d07c9f022049d05c6b205246142fbe36441321b26834815893a23d4fb0c3a28700f29e07fc0121032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e300000000");

        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to me.";

        tx.verify_reserve_proof(&message, &wallet).unwrap();
    }
}
