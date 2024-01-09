#[cfg(feature = "use-esplora-blocking")]
mod regtestenv;
#[cfg(feature = "use-esplora-blocking")]
use bdk::bitcoin::Network;
#[cfg(feature = "use-esplora-blocking")]
use bdk::blockchain::esplora::EsploraBlockchain;
#[cfg(feature = "use-esplora-blocking")]
use bdk::blockchain::{Blockchain, GetHeight};
#[cfg(feature = "use-esplora-blocking")]
use bdk::database::memory::MemoryDatabase;
#[cfg(feature = "use-esplora-blocking")]
use bdk::wallet::{SyncOptions, Wallet};
#[cfg(feature = "use-esplora-blocking")]
use bdk::Error;
#[cfg(feature = "use-esplora-blocking")]
use bdk::SignOptions;
#[cfg(feature = "use-esplora-blocking")]
use bdk_reserves::reserves::*;
#[cfg(feature = "use-esplora-blocking")]
use electrsd::bitcoind::bitcoincore_rpc::bitcoin::Address;
#[cfg(feature = "use-esplora-blocking")]
use esplora_client::Builder;
#[cfg(feature = "use-esplora-blocking")]
use regtestenv::RegTestEnv;
#[cfg(feature = "use-esplora-blocking")]
use std::str::FromStr;

fn construct_wallet(desc: &str, network: Network) -> Result<Wallet<MemoryDatabase>, Error> {
    let wallet = Wallet::new(desc, None, network, MemoryDatabase::default())?;

    Ok(wallet)
}

#[test]
#[cfg(feature = "use-esplora-blocking")]
fn point_in_time() {
    let wallet = construct_wallet(
        "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)",
        Network::Regtest,
    )
    .unwrap();

    let regtestenv = RegTestEnv::new();
    regtestenv.generate(&[&wallet]);
    let esplora_url = format!("http://{}", regtestenv.esplora_url().as_ref().unwrap());
    let client = Builder::new(&esplora_url).build_blocking().unwrap();
    let blockchain = EsploraBlockchain::from_client(client, 20);
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

    let new_txouts_point_in_time = blockchain.txout_set_at_height(old_height);
    let spendable = proof
        .verify_reserve_proof(message, new_txouts_point_in_time)
        .unwrap();
    assert_eq!(spendable, old_balance.confirmed);
}
