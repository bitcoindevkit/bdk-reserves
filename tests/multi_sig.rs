use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::key::{PrivateKey, PublicKey};
use bdk::bitcoin::util::psbt::PartiallySignedTransaction as PSBT;
use bdk::bitcoin::Network;
use bdk::blockchain::{noop_progress, ElectrumBlockchain};
use bdk::database::memory::MemoryDatabase;
use bdk::electrum_client::Client;
use bdk::wallet::{AddressIndex, Wallet};
use bdk::Error;
use bdk::SignOptions;
use bdk_reserves::reserves::*;
use rstest::rstest;

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

#[rstest]
#[case(
    MultisigType::Wsh,
    "tb1qnmhmxkaqqz4lrruhew5mk6zqr0ezstn3stj6c3r2my6hgkescm0sg3qc0r"
)]
#[case(MultisigType::ShWsh, "2NDTiUegP4NwKMnxXm6KdCL1B1WHamhZHC1")]
#[case(MultisigType::P2sh, "2N7yrzYXgQzNQQuHNTjcP3iwpzFVsqe6non")]
fn test_proof_multisig(
    #[case] script_type: MultisigType,
    #[case] expected_address: &'static str,
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

    let spendable = wallet1.verify_proof(&psbt, &message, None)?;
    assert_eq!(spendable, balance);

    Ok(())
}
