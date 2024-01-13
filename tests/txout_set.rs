#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
mod regtestenv;

#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk::bitcoin::Network;
#[cfg(feature = "electrum")]
use bdk::blockchain::electrum::ElectrumBlockchain;
#[cfg(feature = "use-esplora-blocking")]
use bdk::blockchain::esplora::EsploraBlockchain;
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk::blockchain::{Blockchain, GetHeight};
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk::database::memory::MemoryDatabase;
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk::wallet::{SyncOptions, Wallet};
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk::Error;
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk::SignOptions;
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk_reserves::reserves::*;
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use electrsd::bitcoind::bitcoincore_rpc::bitcoin::Address;

#[cfg(feature = "electrum")]
use electrum_client::Client as ElectrumClient;

#[cfg(feature = "use-esplora-blocking")]
use esplora_client::{BlockingClient as EsploraClient, Builder};
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use regtestenv::RegTestEnv;
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use std::str::FromStr;

#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
fn construct_wallet(desc: &str, network: Network) -> Result<Wallet<MemoryDatabase>, Error> {
    let wallet = Wallet::new(desc, None, network, MemoryDatabase::default())?;

    Ok(wallet)
}

#[cfg(feature = "use-esplora-blocking")]
fn point_in_time<B, C>(regtestenv: RegTestEnv, blockchain: B)
where
    B: Blockchain + GetHeight + std::ops::Deref<Target = C>,
    C: for<'b> HistoricalTxOutQuery<'b> + for<'b> TipTxOutQuery<'b>,
    for<'b> <C as HistoricalTxOutQuery<'b>>::Target: TxOutSet + 'b,
    for<'b> <C as TipTxOutQuery<'b>>::Target: TxOutSet + 'b,
{
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Regtest,
    )
    .unwrap();

    regtestenv.generate(&[&wallet]);
    wallet.sync(&blockchain, SyncOptions::default()).unwrap();
    let old_height = blockchain.get_height().unwrap();
    let old_balance = wallet.get_balance().unwrap();

    let message = "This belonged to me.";
    let mut psbt = wallet.create_proof(message).unwrap();
    let signopts = SignOptions {
        trust_witness_utxo: true,
        ..Default::default()
    };
    let finalized = wallet.sign(&mut psbt, signopts.clone()).unwrap();
    let proof = psbt;
    assert!(finalized);

    let txouts_point_in_time = blockchain.txout_set_at_height(old_height);

    let spendable = proof
        .verify_reserve_proof(message, txouts_point_in_time)
        .unwrap();
    assert_eq!(spendable, old_balance.confirmed);

    proof
        .verify_reserve_proof(message, blockchain.txout_set_at_tip())
        .unwrap();

    const MY_FOREIGN_ADDR: &str = "mpSFfNURcFTz2yJxBzRY9NhnozxeJ2AUC8";
    let foreign_addr = Address::from_str(MY_FOREIGN_ADDR).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(foreign_addr.script_pubkey(), 1_000)
        .fee_rate(bdk::FeeRate::from_sat_per_vb(2.0));

    let (mut psbt, _) = builder.finish().unwrap();
    let finalized = wallet.sign(&mut psbt, signopts).unwrap();
    assert!(finalized);
    blockchain.broadcast(&psbt.extract_tx()).unwrap();
    regtestenv.generate_to_address(6, &foreign_addr);
    wallet.sync(&blockchain, SyncOptions::default()).unwrap();

    let new_balance = wallet.get_balance().unwrap();
    assert_ne!(old_balance, new_balance);

    // creating a new object is not necessary, but illustrates that no state is being saved across
    // calls to verify_reserve_proof
    let new_txouts_point_in_time = blockchain.txout_set_at_height(old_height);
    let spendable = proof
        .verify_reserve_proof(message, new_txouts_point_in_time)
        .unwrap();
    assert_eq!(spendable, old_balance.confirmed);

    let new_height = blockchain.get_height().unwrap();
    let new_txouts_point_in_time = blockchain.txout_set_at_height(new_height);

    proof
        .verify_reserve_proof(message, new_txouts_point_in_time)
        .expect_err("expect proof utxos to be spent");

    proof
        .verify_reserve_proof(message, blockchain.txout_set_at_tip())
        .expect_err("expect proof utxos to be spent at tip");
}

#[cfg(feature = "electrum")]
fn confirmed_by<B, C>(regtestenv: RegTestEnv, blockchain: B)
where
    B: Blockchain + GetHeight + std::ops::Deref<Target = C>,
    C: for<'b> MaxHeightTxOutQuery<'b> + for<'b> TipTxOutQuery<'b>,
    for<'b> <C as MaxHeightTxOutQuery<'b>>::Target: TxOutSet + 'b,
    for<'b> <C as TipTxOutQuery<'b>>::Target: TxOutSet + 'b,
{
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Regtest,
    )
    .unwrap();

    regtestenv.generate(&[&wallet]);
    wallet.sync(&blockchain, SyncOptions::default()).unwrap();
    let old_height = blockchain.get_height().unwrap();
    let old_balance = wallet.get_balance().unwrap();

    let message = "This belonged to me.";
    let mut psbt = wallet.create_proof(message).unwrap();
    let signopts = SignOptions {
        trust_witness_utxo: true,
        ..Default::default()
    };
    let finalized = wallet.sign(&mut psbt, signopts.clone()).unwrap();
    let proof = psbt;
    assert!(finalized);

    let txouts = blockchain.txout_set_confirmed_by_height(old_height);

    let spendable = proof.verify_reserve_proof(message, txouts).unwrap();
    assert_eq!(spendable, old_balance.confirmed);

    let spendable = proof
        .verify_reserve_proof(message, blockchain.txout_set_at_tip())
        .unwrap();
    assert_eq!(spendable, old_balance.confirmed);

    const MY_FOREIGN_ADDR: &str = "mpSFfNURcFTz2yJxBzRY9NhnozxeJ2AUC8";
    let foreign_addr = Address::from_str(MY_FOREIGN_ADDR).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(foreign_addr.script_pubkey(), 1_000)
        .fee_rate(bdk::FeeRate::from_sat_per_vb(2.0));

    let (mut psbt, _) = builder.finish().unwrap();
    let finalized = wallet.sign(&mut psbt, signopts).unwrap();
    assert!(finalized);
    blockchain.broadcast(&psbt.extract_tx()).unwrap();

    let txouts = blockchain.txout_set_confirmed_by_height(old_height);

    proof
        .verify_reserve_proof(message, txouts)
        .expect_err("expect coins to be spent");

    regtestenv.generate_to_address(6, &foreign_addr);
    wallet.sync(&blockchain, SyncOptions::default()).unwrap();

    let new_balance = wallet.get_balance().unwrap();
    assert_ne!(old_balance, new_balance);

    let new_height = blockchain.get_height().unwrap();
    let new_txouts_point_in_time = blockchain.txout_set_confirmed_by_height(new_height);

    proof
        .verify_reserve_proof(message, new_txouts_point_in_time)
        .expect_err("expect proof utxos to be spent");

    proof
        .verify_reserve_proof(message, blockchain.txout_set_at_tip())
        .expect_err("expect proof utxos to be spent at tip");
}

#[test]
#[cfg(feature = "electrum")]
fn test_electrum_confirmed_by() {
    let regtestenv = RegTestEnv::new();
    let electrum_url = regtestenv.electrum_url();
    let client = ElectrumClient::new(electrum_url).unwrap();
    let blockchain = ElectrumBlockchain::from(client);

    confirmed_by::<ElectrumBlockchain, ElectrumClient>(regtestenv, blockchain);
}

#[test]
#[cfg(feature = "use-esplora-blocking")]
fn test_esplora_point_in_time() {
    let regtestenv = RegTestEnv::new();
    let esplora_url = format!("http://{}", regtestenv.esplora_url().as_ref().unwrap());
    let client = Builder::new(&esplora_url).build_blocking().unwrap();
    let blockchain = EsploraBlockchain::from_client(client, 20);

    point_in_time::<EsploraBlockchain, EsploraClient>(regtestenv, blockchain);
}
