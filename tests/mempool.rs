use bdk::bitcoin::Network;
use bdk::blockchain::{noop_progress, Blockchain, ElectrumBlockchain};
use bdk::database::memory::MemoryDatabase;
use bdk::electrum_client::Client;
use bdk::wallet::{AddressIndex, Wallet};
use bdk::Error;
use bdk::SignOptions;
use bdk_reserves::reserves::*;

fn construct_wallet(
    desc: &str,
    network: Network,
) -> Result<Wallet<ElectrumBlockchain, MemoryDatabase>, Error> {
    let client = Client::new("ssl://electrum.blockstream.info:60002")?;
    let wallet = Wallet::new(
        desc,
        None,
        network,
        MemoryDatabase::default(),
        ElectrumBlockchain::from(client),
    )?;

    wallet.sync(noop_progress(), None)?;

    Ok(wallet)
}

#[test]
fn unconfirmed() -> Result<(), ProofError> {
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Testnet,
    )?;

    let balance = wallet.get_balance()?;
    assert!(balance > 10_000, "insufficient balance: {}", balance);
    let addr = wallet.get_address(AddressIndex::New).unwrap();
    assert_eq!(
        addr.to_string(),
        "tb1qexxes4qzr3m6a6mcqrp0d4xexagw08fgxv898e"
    );

    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 1_000)
        .fee_rate(bdk::FeeRate::from_sat_per_vb(2.0));
    let (mut psbt, _) = builder.finish().unwrap();
    let signopts = SignOptions {
        trust_witness_utxo: true,
        ..Default::default()
    };
    let finalized = wallet.sign(&mut psbt, signopts.clone())?;
    assert!(finalized);
    wallet.broadcast(&psbt.extract_tx())?;
    wallet.sync(noop_progress(), None)?;

    let new_balance = wallet.get_balance()?;
    assert_ne!(balance, new_balance);

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(message)?;
    let finalized = wallet.sign(&mut psbt, signopts)?;
    assert!(finalized);

    let spendable = wallet.verify_proof(&psbt, message, None)?;
    assert_eq!(spendable, new_balance);

    Ok(())
}

#[test]
#[should_panic(expected = "NonSpendableInput")]
fn confirmed() {
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Testnet,
    )
    .unwrap();

    let balance = wallet.get_balance().unwrap();
    assert!(balance > 10_000, "insufficient balance: {}", balance);
    let addr = wallet.get_address(AddressIndex::New).unwrap();
    assert_eq!(
        addr.to_string(),
        "tb1qexxes4qzr3m6a6mcqrp0d4xexagw08fgxv898e"
    );

    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 1_000)
        .fee_rate(bdk::FeeRate::from_sat_per_vb(2.0));
    let (mut psbt, _) = builder.finish().unwrap();
    let signopts = SignOptions {
        trust_witness_utxo: true,
        ..Default::default()
    };
    let finalized = wallet.sign(&mut psbt, signopts.clone()).unwrap();
    assert!(finalized);
    wallet.broadcast(&psbt.extract_tx()).unwrap();
    wallet.sync(noop_progress(), None).unwrap();

    let new_balance = wallet.get_balance().unwrap();
    assert_ne!(balance, new_balance);

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(message).unwrap();
    let finalized = wallet.sign(&mut psbt, signopts).unwrap();
    assert!(finalized);

    const CONFIRMATIONS: u32 = 2;
    let current_height = wallet.client().get_height().unwrap();
    let max_confirmation_height = current_height - CONFIRMATIONS;

    let spendable = wallet
        .verify_proof(&psbt, message, Some(max_confirmation_height))
        .unwrap();
    assert_eq!(spendable, new_balance);
}
