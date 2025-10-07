mod regtestenv;
use bdk_electrum::electrum_client::{Client, ElectrumApi};
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_reserves::reserves::*;
use bdk_tx::Signer;
use bdk_wallet::bitcoin::{Amount, FeeRate, Network};
use bdk_wallet::descriptor::Descriptor;
use bdk_wallet::{KeychainKind, Wallet};
use regtestenv::RegTestEnv;
use secp256k1::Secp256k1;

#[test]
fn unconfirmed() -> Result<(), ProofError> {
    let descriptor = "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)";
    let mut wallet = Wallet::create_single(descriptor)
        .network(Network::Regtest)
        .create_wallet_no_persist()?;
    let secp = Secp256k1::new();
    let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor).unwrap();
    let signer = Signer(keymap.into_iter().collect());

    let regtestenv = RegTestEnv::new();
    regtestenv.generate(&mut [&mut wallet], &[&signer]);

    let client: BdkElectrumClient<Client> =
        BdkElectrumClient::new(electrum_client::Client::new(regtestenv.electrum_url()).unwrap());

    sync(&mut wallet, &client);
    let balance = wallet.balance();
    assert!(
        balance.confirmed > Amount::from_sat(10_000),
        "insufficient balance: {}",
        balance.confirmed
    );
    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    assert_eq!(
        addr.to_string(),
        "bcrt1qexxes4qzr3m6a6mcqrp0d4xexagw08fgy97gss"
    );

    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_sat(1_000))
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
    let mut psbt = builder.finish().unwrap();
    psbt.sign(&signer, &secp).unwrap();
    client
        .transaction_broadcast(&psbt.extract_tx().unwrap())
        .unwrap();
    sync(&mut wallet, &client);

    let new_balance = wallet.balance();
    assert_ne!(balance, new_balance);

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(message)?;
    psbt.sign(&signer, &secp).unwrap();

    let spendable = wallet.verify_proof(&psbt, message, None)?;
    dbg!(&new_balance);
    assert!(
        spendable <= new_balance.untrusted_pending + new_balance.confirmed,
        "spendable ({}) <= new_balance.untrusted_pending + new_balance.confirmed ({})",
        spendable,
        new_balance.untrusted_pending + new_balance.confirmed
    );

    Ok(())
}

#[test]
#[should_panic(expected = "NonSpendableInput")]
fn confirmed() {
    let descriptor = "wpkh(cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r)";
    let mut wallet = Wallet::create_single(descriptor)
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .unwrap();
    let secp = Secp256k1::new();
    let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor).unwrap();
    let signer = Signer(keymap.into_iter().collect());

    let regtestenv = RegTestEnv::new();
    regtestenv.generate(&mut [&mut wallet], &[&signer]);

    let client: BdkElectrumClient<Client> =
        BdkElectrumClient::new(electrum_client::Client::new(regtestenv.electrum_url()).unwrap());

    sync(&mut wallet, &client);
    let balance = wallet.balance();
    assert!(
        balance.confirmed > Amount::from_sat(10_000),
        "insufficient balance: {}",
        balance
    );
    let addr = wallet.reveal_next_address(KeychainKind::External);
    assert_eq!(
        addr.to_string(),
        "bcrt1qexxes4qzr3m6a6mcqrp0d4xexagw08fgy97gss"
    );

    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_sat(1_000))
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
    let mut psbt = builder.finish().unwrap();
    psbt.sign(&signer, &secp).unwrap();
    client
        .transaction_broadcast(&psbt.extract_tx().unwrap())
        .unwrap();
    sync(&mut wallet, &client);

    let new_balance = wallet.balance();
    assert_ne!(balance, new_balance);

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(message).unwrap();
    psbt.sign(&signer, &secp).unwrap();

    const CONFIRMATIONS: usize = 2;
    let current_height = client.inner.block_headers_subscribe().unwrap().height;
    assert_eq!(current_height, 117);
    let max_confirmation_height = current_height - CONFIRMATIONS;

    let spendable = wallet
        .verify_proof(&psbt, message, Some(max_confirmation_height))
        .unwrap();
    assert_eq!(spendable, new_balance.confirmed);
}

fn sync(wallet: &mut Wallet, client: &BdkElectrumClient<Client>) {
    const BATCH_SIZE: usize = 5;

    let sync_req = wallet.start_sync_with_revealed_spks().build();
    let update = client.sync(sync_req, BATCH_SIZE, true).unwrap();
    wallet.apply_update(update).unwrap();
}
