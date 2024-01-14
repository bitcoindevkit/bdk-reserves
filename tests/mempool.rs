mod regtestenv;
use bdk::bitcoin::Network;
use bdk::blockchain::{electrum::ElectrumBlockchain, Blockchain, GetHeight};
use bdk::database::memory::MemoryDatabase;
use bdk::electrum_client::Client;
use bdk::wallet::{AddressIndex, SyncOptions, Wallet};
use bdk::Error;
use bdk::SignOptions;
use bdk_reserves::reserves::*;
use regtestenv::RegTestEnv;

fn construct_wallet(desc: &str, network: Network) -> Result<Wallet<MemoryDatabase>, Error> {
    let wallet = Wallet::new(desc, None, network, MemoryDatabase::default())?;

    Ok(wallet)
}

#[test]
fn unconfirmed() -> Result<(), ProofError> {
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Regtest,
    )?;

    let regtestenv = RegTestEnv::new();
    regtestenv.generate(&[&wallet]);
    let client = Client::new(regtestenv.electrum_url()).unwrap();
    let blockchain = ElectrumBlockchain::from(client);
    wallet.sync(&blockchain, SyncOptions::default())?;

    let balance = wallet.get_balance()?;
    assert!(
        balance.confirmed > 10_000,
        "insufficient balance: {}",
        balance.confirmed
    );
    let addr = wallet.get_address(AddressIndex::New).unwrap();
    assert_eq!(
        addr.to_string(),
        "bcrt1qexxes4qzr3m6a6mcqrp0d4xexagw08fgy97gss"
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

    let tx = psbt.extract_tx();

    let spendable = tx.verify_reserve_proof(message, &wallet)?;
    assert_eq!(
        spendable,
        new_balance.untrusted_pending + new_balance.confirmed
    );

    Ok(())
}

#[test]
#[should_panic(expected = "OutpointNotFound")]
fn confirmed() {
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Regtest,
    )
    .unwrap();

    let regtestenv = RegTestEnv::new();
    regtestenv.generate(&[&wallet]);
    let client = Client::new(regtestenv.electrum_url()).unwrap();
    let blockchain = ElectrumBlockchain::from(client);
    wallet.sync(&blockchain, SyncOptions::default()).unwrap();

    let balance = wallet.get_balance().unwrap();
    assert!(
        balance.confirmed > 10_000,
        "insufficient balance: {}",
        balance
    );
    let addr = wallet.get_address(AddressIndex::New).unwrap();
    assert_eq!(
        addr.to_string(),
        "bcrt1qexxes4qzr3m6a6mcqrp0d4xexagw08fgy97gss"
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

#[test]
#[should_panic(expected = "OutpointNotFound")]
fn confirmed_tx() {
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Regtest,
    )
    .unwrap();

    let regtestenv = RegTestEnv::new();
    regtestenv.generate(&[&wallet]);
    let client = Client::new(regtestenv.electrum_url()).unwrap();
    let blockchain = ElectrumBlockchain::from(client);
    wallet.sync(&blockchain, SyncOptions::default()).unwrap();

    let balance = wallet.get_balance().unwrap();
    assert!(
        balance.confirmed > 10_000,
        "insufficient balance: {}",
        balance
    );
    let addr = wallet.get_address(AddressIndex::New).unwrap();
    assert_eq!(
        addr.to_string(),
        "bcrt1qexxes4qzr3m6a6mcqrp0d4xexagw08fgy97gss"
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

    let tx = psbt.extract_tx();

    let spendable = tx
        .verify_reserve_proof(
            message,
            wallet.txout_set_confirmed_by_height(max_confirmation_height),
        )
        .unwrap();
    assert_eq!(spendable, new_balance.confirmed);
}
