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

use bdk_wallet::bitcoin::blockdata::opcodes;
use bdk_wallet::bitcoin::blockdata::script::{Builder, Script, ScriptBuf};
use bdk_wallet::bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bdk_wallet::bitcoin::consensus::encode::serialize;
use bdk_wallet::bitcoin::hash_types::Txid;
use bdk_wallet::bitcoin::hashes::{Hash, hash160, sha256d};
use bdk_wallet::bitcoin::psbt::ExtractTxError;
use bdk_wallet::bitcoin::psbt::{Input, Psbt};
use bdk_wallet::bitcoin::sighash::EcdsaSighashType;
use bdk_wallet::bitcoin::{Amount, PubkeyHash, Sequence};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::{AddForeignUtxoError, TxOrdering, Wallet};
use bdk_wallet::{error::CreateTxError, signer::SignerError};
use units::weight::Weight;

/// The API for proof of reserves
pub trait ProofOfReserves {
    /// Create a proof for all spendable UTXOs in a wallet
    fn create_proof(&mut self, message: &str) -> Result<Psbt, ProofError>;

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
        psbt: &Psbt,
        message: &str,
        max_block_height: Option<usize>,
    ) -> Result<Amount, ProofError>;
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
    /// Found an input other than the challenge which is not spendable. Holds the position of the input.
    NonSpendableInput(usize),
    /// Found an input that has no signature at position
    NotSignedInput(usize),
    /// Found an input with an unsupported SIGHASH type at position
    UnsupportedSighashType(usize),
    /// Found an input that is neither witness nor legacy at position
    NeitherWitnessNorLegacy(usize),
    /// Signature validation failed
    SignatureValidation(usize, String),
    /// The output is not valid
    InvalidOutput,
    /// Input and output values are not equal, implying a miner fee
    InAndOutValueNotEqual,
    /// No matching outpoint found
    OutpointNotFound(usize),
    /// Failed to retrieve the block height of a Tx or UTXO
    MissingConfirmationInfo,
    /// Error adding foreign UTXO
    ForeignUtxo(AddForeignUtxoError),
    /// Failed to create a transaction
    TxError(CreateTxError),
    /// Failed to extract TX from a PSBT
    TxExtraction(Box<ExtractTxError>),
    /// Failed to construct a Wallet
    Wallet(bdk_wallet::descriptor::error::Error),
    /// Failed to sign a transaction
    Sign(SignerError),
}

impl From<AddForeignUtxoError> for ProofError {
    fn from(error: AddForeignUtxoError) -> Self {
        ProofError::ForeignUtxo(error)
    }
}

impl From<CreateTxError> for ProofError {
    fn from(error: CreateTxError) -> Self {
        ProofError::TxError(error)
    }
}

impl From<ExtractTxError> for ProofError {
    fn from(error: ExtractTxError) -> Self {
        ProofError::TxExtraction(Box::new(error))
    }
}

impl From<bdk_wallet::descriptor::error::Error> for ProofError {
    fn from(error: bdk_wallet::descriptor::error::Error) -> Self {
        ProofError::Wallet(error)
    }
}

impl From<SignerError> for ProofError {
    fn from(error: SignerError) -> Self {
        ProofError::Sign(error)
    }
}

impl ProofOfReserves for Wallet {
    fn create_proof(&mut self, message: &str) -> Result<Psbt, ProofError> {
        if message.is_empty() {
            return Err(ProofError::ChallengeInputMismatch);
        }
        let challenge_txin = challenge_txin(message);
        let challenge_psbt_inp = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
            }),
            final_script_sig: Some(Script::new().into()), /* "finalize" the input with an empty scriptSig */
            ..Default::default()
        };

        let pkh = PubkeyHash::from_raw_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = ScriptBuf::new_p2pkh(&pkh);

        let mut builder = self.build_tx();
        builder
            .drain_wallet()
            .add_foreign_utxo(
                challenge_txin.previous_output,
                challenge_psbt_inp,
                Weight::from_wu(42),
            )?
            .fee_absolute(Amount::from_sat(0))
            .only_witness_utxo()
            .current_height(0)
            .drain_to(out_script_unspendable)
            .ordering(TxOrdering::Untouched);
        let psbt = builder.finish()?;

        Ok(psbt)
    }

    fn verify_proof(
        &self,
        psbt: &Psbt,
        message: &str,
        max_block_height: Option<usize>,
    ) -> Result<Amount, ProofError> {
        // verify the proof UTXOs are still spendable
        let unspents = self
            .list_unspent()
            .map(|utxo| {
                if max_block_height.is_none() {
                    Ok((utxo, None))
                } else {
                    let tx_details = self.get_tx(utxo.outpoint.txid);
                    if let Some(tx_details) = tx_details {
                        if let ChainPosition::<_>::Confirmed {
                            anchor,
                            transitively: _,
                        } = tx_details.chain_position
                        {
                            Ok((utxo, Some(anchor.block_id.height as usize)))
                        } else {
                            Ok((utxo, None))
                        }
                    } else {
                        Err(ProofError::MissingConfirmationInfo)
                    }
                }
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
        let outpoints = unspents
            .iter()
            .filter(|(_utxo, block_height)| {
                block_height.unwrap_or(usize::MAX) <= max_block_height.unwrap_or(usize::MAX)
            })
            .map(|(utxo, _)| (utxo.outpoint, utxo.txout.clone()))
            .collect();

        verify_proof(psbt, message, outpoints)
    }
}

/// Make sure this is a proof, and not a spendable transaction.
/// Make sure the proof is valid.
/// Currently proofs can only be validated against the tip of the chain.
/// If some of the UTXOs in the proof were spent in the meantime, the proof will fail.
/// We can currently not validate whether it was valid at a certain block height.
/// Since the caller provides the outpoints, he is also responsible to make sure they have enough confirmations.
/// Returns the spendable amount of the proof.
pub fn verify_proof(
    psbt: &Psbt,
    message: &str,
    outpoints: Vec<(OutPoint, TxOut)>,
) -> Result<Amount, ProofError> {
    if psbt.outputs.len() != 1 || psbt.unsigned_tx.output.len() != 1 {
        return Err(ProofError::WrongNumberOfOutputs);
    }
    if psbt.inputs.len() <= 1 || psbt.unsigned_tx.input.len() <= 1 {
        return Err(ProofError::WrongNumberOfInputs);
    }

    let tx = psbt.clone().extract_tx()?;

    if tx.output.len() != 1 {
        return Err(ProofError::WrongNumberOfOutputs);
    }
    if tx.input.len() <= 1 {
        return Err(ProofError::WrongNumberOfInputs);
    }

    // verify the challenge txin
    let challenge_txin = challenge_txin(message);
    if tx.input[0].previous_output != challenge_txin.previous_output {
        return Err(ProofError::ChallengeInputMismatch);
    }

    // verify the proof UTXOs are still spendable
    if let Some((i, _inp)) = tx
        .input
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_i, inp)| !outpoints.iter().any(|op| op.0 == inp.previous_output))
    {
        return Err(ProofError::NonSpendableInput(i));
    }

    // verify that the inputs are signed, except the challenge
    if let Some((i, _inp)) = psbt
        .inputs
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_i, inp)| inp.final_script_sig.is_none() && inp.final_script_witness.is_none())
    {
        return Err(ProofError::NotSignedInput(i));
    }

    // Verify the SIGHASH
    if let Some((i, _psbt_in)) = psbt.inputs.iter().enumerate().find(|(_i, psbt_in)| {
        psbt_in.sighash_type.is_some() && psbt_in.sighash_type != Some(EcdsaSighashType::All.into())
    }) {
        return Err(ProofError::UnsupportedSighashType(i));
    }

    // calculate the spendable amount of the proof
    let sum = tx
        .input
        .iter()
        .map(|tx_in| {
            if let Some(op) = outpoints.iter().find(|op| op.0 == tx_in.previous_output) {
                op.1.value
            } else {
                Amount::from_sat(0)
            }
        })
        .sum();

    // inflow and outflow being equal means no miner fee
    if tx.output[0].value != sum {
        return Err(ProofError::InAndOutValueNotEqual);
    }

    // verify the unspendable output
    let pkh = PubkeyHash::from_raw_hash(hash160::Hash::hash(&[0]));
    let out_script_unspendable = ScriptBuf::new_p2pkh(&pkh);

    if tx.output[0].script_pubkey != out_script_unspendable {
        return Err(ProofError::InvalidOutput);
    }

    let serialized_tx = serialize(&tx);

    // Verify other inputs against prevouts.
    if let Some((i, res)) = tx
        .input
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, tx_in)| {
            if let Some(op) = outpoints.iter().find(|op| op.0 == tx_in.previous_output) {
                (i, Ok(op.1.clone()))
            } else {
                (i, Err(ProofError::OutpointNotFound(i)))
            }
        })
        .map(|(i, res)| match res {
            Ok(txout) => (
                i,
                bitcoinconsensus::verify(
                    txout.script_pubkey.to_bytes().as_slice(),
                    txout.value.to_sat(),
                    &serialized_tx,
                    i,
                )
                .map_err(|e| ProofError::SignatureValidation(i, format!("{:?}", e))),
            ),
            Err(err) => (i, Err(err)),
        })
        .find(|(_i, res)| res.is_err())
    {
        return Err(ProofError::SignatureValidation(
            i,
            format!("{:?}", res.err().unwrap()),
        ));
    }

    Ok(sum)
}

/// Construct a challenge input with the message
fn challenge_txin(message: &str) -> TxIn {
    let message = "Proof-of-Reserves: ".to_string() + message;
    let message = sha256d::Hash::hash(message.as_bytes());
    TxIn {
        previous_output: OutPoint::new(Txid::from_raw_hash(message), 0),
        sequence: Sequence(0xFFFFFFFF),
        ..Default::default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk_wallet::SignOptions;
    use bdk_wallet::bitcoin::{Address, Network, Witness};
    use bdk_wallet::test_utils::get_funded_wallet_single;
    use std::str::FromStr;

    #[test]
    fn test_proof() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (mut wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = wallet.create_proof(message).unwrap();

        let psbt_b64 = psbt.to_string();

        let expected = r#"cHNidP8BAH4CAAAAAmw1RvG4UzfnSafpx62EPTyha6VslP0Er7n3TxjEpeBeAAAAAAD/////MQvsP2eDTCk3vWfQJ50IOFWLwuTHPsnYikR1hosdK0sAAAAAAP3///8BUMMAAAAAAAAZdqkUn3/QltN+0sDj9/DPySS+70/862iIrAAAAAAAAQEKAAAAAAAAAAABUQEHAAABAR9QwwAAAAAAABYAFOzlJlcQU9qGRUyeBmd56vnRUC5qIgYDKwVYB4vsOGlKhJM9ZZMD4lddrn6RaFkRRUEVv9ZEh+ME7OUmVwAA"#;

        assert_eq!(psbt_b64, expected);

        let signopts = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        wallet.sign(&mut psbt, signopts).unwrap();

        let spendable = wallet.verify_proof(&psbt, message, None).unwrap();
        assert_eq!(spendable, Amount::from_sat(50_000));

        let psbt_b64 = psbt.to_string();

        let expected = r#"cHNidP8BAH4CAAAAAmw1RvG4UzfnSafpx62EPTyha6VslP0Er7n3TxjEpeBeAAAAAAD/////MQvsP2eDTCk3vWfQJ50IOFWLwuTHPsnYikR1hosdK0sAAAAAAP3///8BUMMAAAAAAAAZdqkUn3/QltN+0sDj9/DPySS+70/862iIrAAAAAAAAQEKAAAAAAAAAAABUQEHAAABAR9QwwAAAAAAABYAFOzlJlcQU9qGRUyeBmd56vnRUC5qAQhrAkcwRAIgMjk39sEdlh9VEb0GOKNy+C/X4yiZd4/AteVnZjdSuPYCIBQKVpBGTpUSZNoXqT93EucKLLFVQnLJIkPXKjRYO4eJASEDKwVYB4vsOGlKhJM9ZZMD4lddrn6RaFkRRUEVv9ZEh+MAAA=="#;

        assert_eq!(psbt_b64, expected);
    }

    #[test]
    #[should_panic(expected = "\"Key too short (<66 char), doesn't match any format\"")]
    fn invalid_descriptor() {
        let descriptor = "wpkh(cVpPVqXRyPcFW)";
        let (mut wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let _psbt = wallet.create_proof(message).unwrap();
    }

    #[test]
    #[should_panic(expected = "ChallengeInputMismatch")]
    fn empty_message() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (mut wallet, _) = get_funded_wallet_single(descriptor);

        let message = "";
        let _psbt = wallet.create_proof(message).unwrap();
    }

    fn get_signed_proof() -> Psbt {
        let psbt = "cHNidP8BAH4BAAAAAmw1RvG4UzfnSafpx62EPTyha6VslP0Er7n3TxjEpeBeAAAAAAD/////MQvsP2eDTCk3vWfQJ50IOFWLwuTHPsnYikR1hosdK0sAAAAAAP3///8BUMMAAAAAAAAZdqkUn3/QltN+0sDj9/DPySS+70/862iIrAAAAAAAAQEKAAAAAAAAAAABUQEHAAABAR9QwwAAAAAAABYAFOzlJlcQU9qGRUyeBmd56vnRUC5qAQhrAkcwRAIgR9XtbnBY0jUe9zXI0kCEzEua5pHm6Bal6mCHNBmTTIECIE2NbjpRjD6/nZv72GQ7qPZ1Sdo3BPps0cBN1DOsB+S+ASEDKwVYB4vsOGlKhJM9ZZMD4lddrn6RaFkRRUEVv9ZEh+MAAA==";
        Psbt::from_str(psbt).unwrap()
    }

    #[test]
    fn verify_internal() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let spendable = wallet.verify_proof(&psbt, message, None).unwrap();
        assert_eq!(spendable, Amount::from_sat(50_000));
    }

    #[test]
    #[should_panic(expected = "NonSpendableInput")]
    fn verify_internal_1990() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let spendable = wallet.verify_proof(&psbt, message, Some(1990)).unwrap();
        assert_eq!(spendable, Amount::from_sat(0));
    }

    #[test]
    fn verify_internal_2000() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let spendable = wallet.verify_proof(&psbt, message, Some(2000)).unwrap();
        assert_eq!(spendable, Amount::from_sat(50_000));
    }

    #[test]
    fn verify_external() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let psbt = get_signed_proof();
        let outpoints = wallet
            .list_unspent()
            .map(|utxo| (utxo.outpoint, utxo.txout))
            .collect();
        let spendable = verify_proof(&psbt, message, outpoints).unwrap();

        assert_eq!(spendable, Amount::from_sat(50_000));
    }

    #[test]
    #[should_panic(expected = "ChallengeInputMismatch")]
    fn wrong_message() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "Wrong message!";
        let psbt = get_signed_proof();
        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongNumberOfInputs")]
    fn too_few_inputs() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.input.truncate(1);
        psbt.inputs.truncate(1);

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongNumberOfOutputs")]
    fn no_output() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs.clear();
        psbt.unsigned_tx.output.clear();

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "NotSignedInput")]
    fn missing_signature() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].final_script_sig = None;
        psbt.inputs[1].final_script_witness = None;

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "SignatureValidation")]
    fn invalid_signature() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].final_script_sig = None;

        let invalid_signature = bdk_wallet::bitcoin::secp256k1::ecdsa::Signature::from_str("3045022100f3b7b0b1400287766edfe8ba66bc0412984cdb97da6bb4092d5dc63a84e1da6f02204da10796361dbeaeead8f68a23157dffa23b356ec14ec2c0c384ad68d582bb14").unwrap();
        let invalid_signature =
            bdk_wallet::bitcoin::ecdsa::Signature::sighash_all(invalid_signature);

        let mut invalid_witness = Witness::new();
        invalid_witness.push_ecdsa_signature(&invalid_signature);

        psbt.inputs[1].final_script_witness = Some(invalid_witness);

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedSighashType(1)")]
    fn wrong_sighash_type() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.inputs[1].sighash_type = Some(EcdsaSighashType::SinglePlusAnyoneCanPay.into());

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    fn burner_output() {
        let psbt = get_signed_proof();

        let pkh = PubkeyHash::from_raw_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = ScriptBuf::new_p2pkh(&pkh);
        assert_eq!(
            psbt.unsigned_tx.output[0].script_pubkey,
            out_script_unspendable
        );

        let addr_unspendable = Address::p2pkh(pkh, Network::Bitcoin);
        assert_eq!(
            addr_unspendable.to_string(),
            "1FYMZEHnszCHKTBdFZ2DLrUuk3dGwYKQxh"
        );
        // https://mempool.space/de/address/1FYMZEHnszCHKTBdFZ2DLrUuk3dGwYKQxh
        // https://bitcoin.stackexchange.com/questions/65969/invalid-public-key-was-spent-how-was-this-possible

        let addr_unspendable_testnet = Address::p2pkh(pkh, Network::Testnet);
        assert_eq!(
            addr_unspendable_testnet.to_string(),
            "mv4JrHNmh1dY6ZfEy7zbAmhEc3Dyr8ULqX"
        );
        // this address can be discovered in the transaction in https://ulrichard.ch/blog/?p=2566
    }

    #[test]
    #[should_panic(expected = "InvalidOutput")]
    fn invalid_output() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();

        let pkh = PubkeyHash::from_raw_hash(hash160::Hash::hash(&[0, 1, 2, 3]));
        let out_script_unspendable = ScriptBuf::new_p2pkh(&pkh);
        psbt.unsigned_tx.output[0].script_pubkey = out_script_unspendable;

        wallet.verify_proof(&psbt, message, None).unwrap();
    }

    #[test]
    #[should_panic(expected = "InAndOutValueNotEqual")]
    fn sum_mismatch() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _) = get_funded_wallet_single(descriptor);

        let message = "This belongs to me.";
        let mut psbt = get_signed_proof();
        psbt.unsigned_tx.output[0].value = Amount::from_sat(123);

        wallet.verify_proof(&psbt, message, None).unwrap();
    }
}
