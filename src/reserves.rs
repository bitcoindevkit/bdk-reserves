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
use bdk::bitcoin::blockdata::transaction::{OutPoint, SigHashType, TxIn, TxOut};
use bdk::bitcoin::consensus::encode::serialize;
use bdk::bitcoin::hash_types::{PubkeyHash, Txid};
use bdk::bitcoin::hashes::{hash160, sha256d, Hash};
use bdk::bitcoin::util::address::Payload;
use bdk::bitcoin::util::psbt::{Input, PartiallySignedTransaction as PSBT};
use bdk::bitcoin::{Address, Network};
use bdk::database::BatchDatabase;
use bdk::wallet::tx_builder::TxOrdering;
use bdk::wallet::Wallet;
use bdk::Error;

/// The API for proof of reserves
pub trait ProofOfReserves {
    /// Create a proof for all spendable UTXOs in a wallet
    fn create_proof(&self, message: &str) -> Result<PSBT, ProofError>;

    /// Make sure this is a proof, and not a spendable transaction.
    /// Make sure the proof is valid.
    /// Currently proofs can only be validated against the tip of the chain.
    /// If some of the UTXOs in the proof were spent in the meantime, the proof will fail.
    /// We can currently not validate whether it was valid at a certain block height.
    /// Returns the spendable amount of the proof.
    fn verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, ProofError>;
}

/// Proof error
#[derive(Debug, PartialEq)]
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
    /// No matching outpoing found
    OutpointNotFound(usize),
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

impl<B, D> ProofOfReserves for Wallet<B, D>
where
    D: BatchDatabase,
{
    fn create_proof(&self, message: &str) -> Result<PSBT, ProofError> {
        let challenge_txin = challenge_txin(message);
        let challenge_psbt_inp = Input {
            witness_utxo: Some(TxOut {
                value: 0,
                script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
            }),
            final_script_sig: Some(Script::default()), /* "finalize" the input with an empty scriptSig */
            ..Default::default()
        };

        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = Address {
            payload: Payload::PubkeyHash(pkh),
            network: self.network(),
        }
        .script_pubkey();

        let mut builder = self.build_tx();
        builder
            .drain_wallet()
            .add_foreign_utxo(challenge_txin.previous_output, challenge_psbt_inp, 42)?
            .fee_absolute(0)
            .only_witness_utxo()
            .drain_to(out_script_unspendable)
            .ordering(TxOrdering::Untouched);
        let (psbt, _details) = builder.finish().map_err(|e| ProofError::BdkError(e))?;

        Ok(psbt)
    }

    fn verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, ProofError> {
        // verify the proof UTXOs are still spendable
        let unspents = self.list_unspent().map_err(|e| ProofError::BdkError(e))?;
        let outpoints = unspents
            .iter()
            .map(|utxo| (utxo.outpoint, utxo.txout.clone()))
            .collect();

        verify_proof(psbt, message, outpoints, self.network())
    }
}

/// Make sure this is a proof, and not a spendable transaction.
/// Make sure the proof is valid.
/// Currently proofs can only be validated against the tip of the chain.
/// If some of the UTXOs in the proof were spent in the meantime, the proof will fail.
/// We can currently not validate whether it was valid at a certain block height.
/// Returns the spendable amount of the proof.
pub fn verify_proof(
    psbt: &PSBT,
    message: &str,
    outpoints: Vec<(OutPoint, TxOut)>,
    network: Network,
) -> Result<u64, ProofError> {
    let tx = psbt.clone().extract_tx();

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
        .find(|(_i, inp)| outpoints.iter().find(|op| op.0 == inp.previous_output) == None)
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
        psbt_in.sighash_type.is_some() && psbt_in.sighash_type != Some(SigHashType::All)
    }) {
        return Err(ProofError::UnsupportedSighashType(i));
    }

    let serialized_tx = serialize(&tx);
    // Verify the challenge input
    if let Some(utxo) = &psbt.inputs[0].witness_utxo {
        if let Err(err) = bitcoinconsensus::verify(
            utxo.script_pubkey.to_bytes().as_slice(),
            utxo.value,
            &serialized_tx,
            0,
        ) {
            return Err(ProofError::SignatureValidation(0, format!("{:?}", err)));
        }
    } else {
        return Err(ProofError::SignatureValidation(
            0,
            "witness_utxo not found for challenge input".to_string(),
        ));
    }
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
                Ok(bitcoinconsensus::verify(
                    txout.script_pubkey.to_bytes().as_slice(),
                    txout.value,
                    &serialized_tx,
                    i,
                )),
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

    // calculate the spendable amount of the proof
    let sum = tx
        .input
        .iter()
        .map(|tx_in| {
            if let Some(op) = outpoints.iter().find(|op| op.0 == tx_in.previous_output) {
                op.1.value
            } else {
                0
            }
        })
        .sum();

    // verify the unspendable output
    let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
    let out_script_unspendable = Address {
        payload: Payload::PubkeyHash(pkh),
        network,
    }
    .script_pubkey();
    if tx.output[0].script_pubkey != out_script_unspendable {
        return Err(ProofError::InvalidOutput);
    }

    // inflow and outflow being equal means no miner fee
    if tx.output[0].value != sum {
        return Err(ProofError::InAndOutValueNotEqual);
    }

    Ok(sum)
}

/// Construct a challenge input with the message
fn challenge_txin(message: &str) -> TxIn {
    let message = "Proof-of-Reserves: ".to_string() + message;
    let message = sha256d::Hash::hash(message.as_bytes());
    TxIn {
        previous_output: OutPoint::new(Txid::from_hash(message), 0),
        sequence: 0xFFFFFFFF,
        ..Default::default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk::bitcoin::secp256k1::Secp256k1;
    use bdk::bitcoin::util::key::{PrivateKey, PublicKey};
    use bdk::bitcoin::Network;
    use bdk::blockchain::{noop_progress, ElectrumBlockchain};
    use bdk::database::memory::MemoryDatabase;
    use bdk::electrum_client::Client;
    use bdk::wallet::{get_funded_wallet, AddressIndex};
    use bdk::SignOptions;
    use rstest::rstest;

    #[rstest(
        descriptor,
        case("wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"),
        case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))"),     // and(pk(Alice),older(6))
        case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))") // and(pk(Alice),after(100000))
    )]
    fn test_proof(descriptor: &'static str) -> Result<(), ProofError> {
        let (wallet, _, _) = get_funded_wallet(descriptor);
        let balance = wallet.get_balance()?;

        let message = "This belongs to me.";
        let mut psbt = wallet.create_proof(&message)?;
        let num_inp = psbt.inputs.len();
        assert!(
            num_inp > 1,
            "num_inp is {} but should be more than 1",
            num_inp
        );

        let finalized = wallet.sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )?;
        let num_sigs = psbt
            .inputs
            .iter()
            .fold(0, |acc, i| acc + i.partial_sigs.len());
        assert_eq!(num_sigs, num_inp - 1);
        assert!(finalized);

        let spendable = wallet.verify_proof(&psbt, &message)?;
        assert_eq!(spendable, balance);

        Ok(())
    }

    #[test]
    #[should_panic(expected = "ChallengeInputMismatch")]
    fn tampered_proof_message() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);
        let balance = wallet.get_balance().unwrap();

        let message_alice = "This belongs to Alice.";
        let mut psbt_alice = wallet.create_proof(&message_alice).unwrap();

        let signopt = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let _finalized = wallet.sign(&mut psbt_alice, signopt).unwrap();

        let spendable = wallet.verify_proof(&psbt_alice, &message_alice).unwrap();
        assert_eq!(spendable, balance);

        // change the message
        let message_bob = "This belongs to Bob.";
        let psbt_bob = wallet.create_proof(&message_bob).unwrap();
        psbt_alice.global.unsigned_tx.input[0].previous_output =
            psbt_bob.global.unsigned_tx.input[0].previous_output;
        psbt_alice.inputs[0].witness_utxo = psbt_bob.inputs[0].witness_utxo.clone();

        let res_alice = wallet.verify_proof(&psbt_alice, &message_alice);
        let res_bob = wallet.verify_proof(&psbt_alice, &message_bob);
        assert!(res_alice.is_err());
        assert!(!res_bob.is_err());
        res_alice.unwrap();
        res_bob.unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedSighashType(1)")]
    fn tampered_proof_sighash_tx() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to Alice.";
        let mut psbt = wallet.create_proof(&message).unwrap();

        let signopt = SignOptions {
            trust_witness_utxo: true,
            allow_all_sighashes: true,
            ..Default::default()
        };

        // set an unsupported sighash
        psbt.inputs[1].sighash_type = Some(SigHashType::Single);

        let _finalized = wallet.sign(&mut psbt, signopt).unwrap();

        let _spendable = wallet.verify_proof(&psbt, &message).unwrap();
    }

    #[test]
    #[should_panic(expected = "InAndOutValueNotEqual")]
    fn tampered_proof_miner_fee() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);

        let message = "This belongs to Alice.";
        let mut psbt = wallet.create_proof(&message).unwrap();

        let signopt = SignOptions {
            trust_witness_utxo: true,
            allow_all_sighashes: true,
            ..Default::default()
        };

        // reduce the output value to grant a miner fee
        psbt.global.unsigned_tx.output[0].value -= 100;

        let _finalized = wallet.sign(&mut psbt, signopt).unwrap();

        let _spendable = wallet.verify_proof(&psbt, &message).unwrap();
    }

    enum MultisigType {
        Wsh,
        ShWsh,
        P2sh,
    }

    fn construct_multisig_wallet(
        signer: &PrivateKey,
        pubkeys: &[PublicKey],
        script_type: &MultisigType,
    ) -> Result<Wallet<ElectrumBlockchain, MemoryDatabase>, Error> {
        let secp = Secp256k1::new();
        let pub_derived = signer.public_key(&secp);

        let (prefix, postfix) = match script_type {
            MultisigType::Wsh => ("wsh(", ")"),
            MultisigType::ShWsh => ("sh(wsh(", "))"),
            MultisigType::P2sh => ("sh(", ")"),
        };
        let prefix = prefix.to_string() + "multi(2,";
        let postfix = postfix.to_string() + ")";
        let desc = pubkeys.iter().enumerate().fold(prefix, |acc, (i, pubkey)| {
            let mut desc = acc;
            if i != 0 {
                desc += ",";
            }
            if *pubkey == pub_derived {
                desc += &signer.to_wif();
            } else {
                desc += &pubkey.to_string();
            }
            desc
        }) + &postfix;

        let client = Client::new("ssl://electrum.blockstream.info:60002")?;
        let wallet = Wallet::new(
            &desc,
            None,
            Network::Testnet,
            MemoryDatabase::default(),
            ElectrumBlockchain::from(client),
        )?;

        wallet.sync(noop_progress(), None)?;

        Ok(wallet)
    }

    #[rstest(
        script_type,
        expected_address,
        case(
            MultisigType::Wsh,
            "tb1qnmhmxkaqqz4lrruhew5mk6zqr0ezstn3stj6c3r2my6hgkescm0sg3qc0r"
        ),
        case(MultisigType::ShWsh, "2NDTiUegP4NwKMnxXm6KdCL1B1WHamhZHC1"),
        case(MultisigType::P2sh, "2N7yrzYXgQzNQQuHNTjcP3iwpzFVsqe6non")
    )]
    fn test_proof_multisig(
        script_type: MultisigType,
        expected_address: &'static str,
    ) -> Result<(), ProofError> {
        let signer1 =
            PrivateKey::from_wif("cQCi6JdidZN5HeiHhjE7zZAJ1XJrZbj6MmpVPx8Ri3Kc8UjPgfbn").unwrap();
        let signer2 =
            PrivateKey::from_wif("cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r").unwrap();
        let signer3 =
            PrivateKey::from_wif("cUPkz3JBZinD1RRU7ngmx8cssqJ4KgBvboq1QZcGfyjqm8L6etRH").unwrap();
        let secp = Secp256k1::new();
        let mut pubkeys = vec![
            signer1.public_key(&secp),
            signer2.public_key(&secp),
            signer3.public_key(&secp),
        ];
        pubkeys.sort_by_key(|item| item.to_string());

        let wallet1 = construct_multisig_wallet(&signer1, &pubkeys, &script_type)?;
        let wallet2 = construct_multisig_wallet(&signer2, &pubkeys, &script_type)?;
        let wallet3 = construct_multisig_wallet(&signer3, &pubkeys, &script_type)?;
        assert_eq!(
            wallet1.get_address(AddressIndex::New)?.to_string(),
            expected_address
        );
        assert_eq!(
            wallet2.get_address(AddressIndex::New)?.to_string(),
            expected_address
        );
        assert_eq!(
            wallet3.get_address(AddressIndex::New)?.to_string(),
            expected_address
        );
        let balance = wallet1.get_balance()?;
        assert!(
            (410000..=420000).contains(&balance),
            "balance is {} but should be between 410000 and 420000",
            balance
        );

        let message = "All my precious coins";
        let mut psbt = wallet1.create_proof(message)?;
        let num_inp = psbt.inputs.len();
        assert!(
            num_inp > 1,
            "num_inp is {} but should be more than 1",
            num_inp
        );

        // returns a tuple with the counts of (partial_sigs, final_script_sig, final_script_witness)
        let count_signatures = |psbt: &PSBT| {
            psbt.inputs.iter().fold((0usize, 0, 0), |acc, i| {
                (
                    acc.0 + i.partial_sigs.len(),
                    acc.1 + if i.final_script_sig.is_some() { 1 } else { 0 },
                    acc.2
                        + if i.final_script_witness.is_some() {
                            1
                        } else {
                            0
                        },
                )
            })
        };

        let signopts = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let finalized = wallet1.sign(&mut psbt, signopts.clone())?;
        assert_eq!(count_signatures(&psbt), (num_inp - 1, 1, 0));
        assert!(!finalized);

        let finalized = wallet2.sign(&mut psbt, signopts.clone())?;
        assert_eq!(
            count_signatures(&psbt),
            ((num_inp - 1) * 2, num_inp, num_inp - 1)
        );
        assert!(finalized);

        // 2 signatures are enough. Just checking what happens...
        let finalized = wallet3.sign(&mut psbt, signopts.clone())?;
        assert_eq!(
            count_signatures(&psbt),
            ((num_inp - 1) * 2, num_inp, num_inp - 1)
        );
        assert!(finalized);

        let finalized = wallet1.finalize_psbt(&mut psbt, signopts)?;
        assert_eq!(
            count_signatures(&psbt),
            ((num_inp - 1) * 2, num_inp, num_inp - 1)
        );
        assert!(finalized);

        let spendable = wallet1.verify_proof(&psbt, &message)?;
        assert_eq!(spendable, balance);

        Ok(())
    }
}
