use bdk::bitcoin::Network;
use bdk::blockchain::{electrum::ElectrumBlockchain, Blockchain, GetHeight};
use bdk::database::memory::MemoryDatabase;
use bdk::electrum_client::Client;
use bdk::wallet::{AddressIndex, SyncOptions, Wallet};
use bdk::Error;
use bdk::SignOptions;
use bdk_reserves::reserves::*;

fn construct_wallet(
    desc: &str,
    network: Network,
) -> Result<(Wallet<MemoryDatabase>, ElectrumBlockchain), Error> {
    let client = Client::new("ssl://electrum.blockstream.info:60002")?;
    let wallet = Wallet::new(desc, None, network, MemoryDatabase::default())?;

    let blockchain = ElectrumBlockchain::from(client);
    wallet.sync(&blockchain, SyncOptions::default())?;

    Ok((wallet, blockchain))
}

#[test]
fn unconfirmed() -> Result<(), ProofError> {
    let (wallet, blockchain) = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Testnet,
    )?;

    let balance = wallet.get_balance()?;
    assert!(
        balance.confirmed > 10_000,
        "insufficient balance: {}",
        balance.confirmed
    );
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
    blockchain.broadcast(&psbt.extract_tx())?;
    wallet.sync(&blockchain, SyncOptions::default())?;

    let new_balance = wallet.get_balance()?;
    assert_ne!(balance, new_balance);

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(message)?;
    let finalized = wallet.sign(&mut psbt, signopts)?;
    assert!(finalized);

    let spendable = wallet.verify_proof(&psbt, message, None)?;
    dbg!(&new_balance);
    assert_eq!(
        spendable,
        new_balance.untrusted_pending + new_balance.confirmed
    );

    Ok(())
}

#[test]
#[should_panic(expected = "NonSpendableInput")]
fn confirmed() {
    let (wallet, blockchain) = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Testnet,
    )
    .unwrap();

    let balance = wallet.get_balance().unwrap();
    assert!(
        balance.confirmed > 10_000,
        "insufficient balance: {}",
        balance
    );
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
    blockchain.broadcast(&psbt.extract_tx()).unwrap();
    wallet.sync(&blockchain, SyncOptions::default()).unwrap();

    let new_balance = wallet.get_balance().unwrap();
    assert_ne!(balance, new_balance);

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(message).unwrap();
    let finalized = wallet.sign(&mut psbt, signopts).unwrap();
    assert!(finalized);

    const CONFIRMATIONS: u32 = 2;
    let current_height = blockchain.get_height().unwrap();
    let max_confirmation_height = current_height - CONFIRMATIONS;

    let spendable = wallet
        .verify_proof(&psbt, message, Some(max_confirmation_height))
        .unwrap();
    assert_eq!(spendable, new_balance.confirmed);
}
