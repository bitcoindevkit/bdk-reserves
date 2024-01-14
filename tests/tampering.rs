use bdk::bitcoin::blockdata::transaction::EcdsaSighashType;
use bdk::wallet::get_funded_wallet;
use bdk::SignOptions;
use bdk_reserves::reserves::*;

#[test]
#[should_panic(expected = "ChallengeInputMismatch")]
fn tampered_proof_message() {
    let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
    let (wallet, _, _) = get_funded_wallet(descriptor);
    let balance = wallet.get_balance().unwrap();

    let message_alice = "This belongs to Alice.";
    let mut psbt_alice = wallet.create_proof(message_alice).unwrap();

    let signopt = SignOptions {
        trust_witness_utxo: true,
        ..Default::default()
    };
    let _finalized = wallet.sign(&mut psbt_alice, signopt).unwrap();

    let spendable = wallet
        .verify_proof(&psbt_alice, message_alice, None)
        .unwrap();
    assert_eq!(spendable, balance.confirmed);

    let tx_alice = psbt_alice.clone().extract_tx();
    let spendable = tx_alice
        .verify_reserve_proof(message_alice, &wallet)
        .unwrap();
    assert_eq!(spendable, balance.confirmed);

    // change the message
    let message_bob = "This belongs to Bob.";
    let psbt_bob = wallet.create_proof(message_bob).unwrap();
    psbt_alice.unsigned_tx.input[0].previous_output = psbt_bob.unsigned_tx.input[0].previous_output;
    psbt_alice.inputs[0].witness_utxo = psbt_bob.inputs[0].witness_utxo.clone();

    let res_alice = wallet.verify_proof(&psbt_alice, message_alice, None);
    let res_bob = wallet.verify_proof(&psbt_alice, message_bob, None);
    assert!(res_alice.is_err());
    assert!(res_bob.is_err());

    let tx_alice = psbt_alice.extract_tx();
    let res_alice = tx_alice.verify_reserve_proof(message_alice, &wallet);
    let tx_bob = psbt_bob.extract_tx();
    let res_bob = tx_bob.verify_reserve_proof(message_bob, &wallet);
    assert!(res_alice.is_err());
    assert!(res_bob.is_err());

    res_alice.unwrap();
}

#[test]
#[should_panic(expected = "UnsupportedSighashType(1)")]
fn tampered_proof_sighash_tx() {
    let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
    let (wallet, _, _) = get_funded_wallet(descriptor);

    let message = "This belongs to Alice.";
    let mut psbt = wallet.create_proof(message).unwrap();

    let signopt = SignOptions {
        trust_witness_utxo: true,
        allow_all_sighashes: true,
        ..Default::default()
    };

    // set an unsupported sighash
    psbt.inputs[1].sighash_type = Some(EcdsaSighashType::Single.into());

    let _finalized = wallet.sign(&mut psbt, signopt).unwrap();

    let _spendable = wallet.verify_proof(&psbt, message, None).unwrap();
}

#[test]
#[should_panic(expected = "InAndOutValueNotEqual")]
fn tampered_proof_miner_fee() {
    let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
    let (wallet, _, _) = get_funded_wallet(descriptor);

    let message = "This belongs to Alice.";
    let mut psbt = wallet.create_proof(message).unwrap();

    let signopt = SignOptions {
        trust_witness_utxo: true,
        allow_all_sighashes: true,
        ..Default::default()
    };

    // reduce the output value to grant a miner fee
    psbt.unsigned_tx.output[0].value -= 100;

    let _finalized = wallet.sign(&mut psbt, signopt).unwrap();

    let _spendable = wallet.verify_proof(&psbt, message, None).unwrap();
}

#[test]
#[should_panic(expected = "InAndOutValueNotEqual")]
fn tampered_proof_miner_fee_tx() {
    let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
    let (wallet, _, _) = get_funded_wallet(descriptor);

    let message = "This belongs to Alice.";
    let mut psbt = wallet.create_proof(message).unwrap();

    let signopt = SignOptions {
        trust_witness_utxo: true,
        allow_all_sighashes: true,
        ..Default::default()
    };

    // reduce the output value to grant a miner fee
    psbt.unsigned_tx.output[0].value -= 100;

    let _finalized = wallet.sign(&mut psbt, signopt).unwrap();

    let tx = psbt.extract_tx();

    let _spendable = tx.verify_reserve_proof(message, &wallet).unwrap();
}
