use bdk_reserves::reserves::*;
use bdk_tx::Signer;
use bdk_wallet::bitcoin::Amount;
use bdk_wallet::descriptor::Descriptor;
use bdk_wallet::test_utils::get_funded_wallet_single;
use secp256k1::Secp256k1;

#[test]
#[should_panic(expected = "ChallengeInputMismatch")]
fn tampered_proof_message() {
    let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
    let (mut wallet, _) = get_funded_wallet_single(descriptor);
    let balance = wallet.balance();

    let message_alice = "This belongs to Alice.";
    let mut psbt_alice = wallet.create_proof(message_alice).unwrap();

    let secp = Secp256k1::new();
    let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor).unwrap();
    let signer = Signer(keymap.into_iter().collect());
    psbt_alice.sign(&signer, &secp).unwrap();

    let spendable = wallet
        .verify_proof(&psbt_alice, message_alice, None)
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
    res_alice.unwrap();
    res_bob.unwrap();
}

#[test]
#[should_panic(expected = "InAndOutValueNotEqual")]
fn tampered_proof_miner_fee() {
    let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
    let (mut wallet, _) = get_funded_wallet_single(descriptor);

    let message = "This belongs to Alice.";
    let mut psbt = wallet.create_proof(message).unwrap();

    // reduce the output value to grant a miner fee
    psbt.unsigned_tx.output[0].value -= Amount::from_sat(100);

    let secp = Secp256k1::new();
    let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor).unwrap();
    let signer = Signer(keymap.into_iter().collect());
    psbt.sign(&signer, &secp).unwrap();

    let _spendable = wallet.verify_proof(&psbt, message, None).unwrap();
}
