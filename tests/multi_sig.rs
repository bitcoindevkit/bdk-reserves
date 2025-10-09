mod regtestenv;
use bdk_reserves::reserves::*;
use bdk_tx::Signer;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::key::{PrivateKey, PublicKey};
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::descriptor::DescriptorPublicKey;
use bdk_wallet::keys::{SinglePriv, SinglePub, SinglePubKey};
use bdk_wallet::miniscript::descriptor::{DescriptorSecretKey, KeyMap};
use bdk_wallet::{KeychainKind, Wallet};
use regtestenv::RegTestEnv;
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
) -> Result<Wallet, ProofError> {
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

    let wallet = Wallet::create_single(desc)
        .network(Network::Regtest)
        .create_wallet_no_persist()?;

    Ok(wallet)
}

#[rstest]
#[case::wsh(
    MultisigType::Wsh,
    "bcrt1qnmhmxkaqqz4lrruhew5mk6zqr0ezstn3stj6c3r2my6hgkescm0s9g276e", (0, 1)
)]
#[case::shwsh(MultisigType::ShWsh, "2NDTiUegP4NwKMnxXm6KdCL1B1WHamhZHC1", (1, 1))]
#[case::p2sh(MultisigType::P2sh, "2N7yrzYXgQzNQQuHNTjcP3iwpzFVsqe6non", (1, 0))]
fn test_proof_multisig(
    #[case] script_type: MultisigType,
    #[case] expected_address: &'static str,
    #[case] count_mult: (u32, usize),
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

    let mut wallet0 = construct_multisig_wallet(&signer1, &pubkeys, &script_type)?;
    let mut wallet1 = construct_multisig_wallet(&signer2, &pubkeys, &script_type)?;
    let mut wallet2 = construct_multisig_wallet(&signer3, &pubkeys, &script_type)?;
    let mut wallets = [&mut wallet0, &mut wallet1, &mut wallet2];
    let signer1 = signer_from_priv(signer1, pubkeys[0]);
    let signer2 = signer_from_priv(signer2, pubkeys[1]);
    let signer3 = signer_from_priv(signer3, pubkeys[2]);
    let signers = [&signer1, &signer2, &signer3];

    wallets
        .iter_mut()
        .enumerate()
        .for_each(|(i, &mut ref mut wallet)| {
            let addr = wallet
                .reveal_next_address(KeychainKind::External)
                .address
                .to_string();
            assert!(
                addr == expected_address,
                "Wallet {} address is {} instead of {}",
                i,
                addr,
                expected_address
            );
        });

    let regtestenv = RegTestEnv::new();
    regtestenv.generate(&mut wallets, &signers);

    wallets.iter().enumerate().for_each(|(i, wallet)| {
        let balance = wallet.balance();
        assert!(
            (49_999_999_256..=49_999_999_598).contains(&balance.confirmed.to_sat()),
            "balance of wallet {} is {} but should be between 49_999_999_256 and 49_999_999_596",
            i,
            balance.confirmed.to_sat()
        );
    });

    let message = "All my precious coins";
    let mut psbt = wallets[2].create_proof(message)?;
    let num_inp = psbt.inputs.len();
    assert!(
        num_inp > 1,
        "num_inp is {} but should be more than 1",
        num_inp
    );

    // returns a tuple with the counts of (partial_sigs, final_script_sig, final_script_witness)
    let count_signatures = |psbt: &Psbt| {
        psbt.inputs.iter().fold((0usize, 0, 0), |acc, i| {
            (
                acc.0 + i.partial_sigs.len(),
                acc.1 + usize::from(i.final_script_sig.is_some()),
                acc.2 + usize::from(i.final_script_witness.is_some()),
            )
        })
    };

    psbt.sign(signers[0], &secp).unwrap();
    assert_eq!(count_signatures(&psbt), (num_inp - 1, 1, 0));

    psbt.sign(signers[1], &secp).unwrap();
    assert_eq!(
        count_signatures(&psbt),
        (0, num_inp.pow(count_mult.0), (num_inp - 1) * count_mult.1)
    );

    // 2 signatures are enough. Just checking what happens...
    psbt.sign(signers[2], &secp).unwrap();
    assert_eq!(
        count_signatures(&psbt),
        (0, num_inp.pow(count_mult.0), (num_inp - 1) * count_mult.1)
    );

    let signopts = bdk_wallet::SignOptions {
        trust_witness_utxo: true,
        //remove_partial_sigs: false,
        ..Default::default()
    };
    let finalized = wallets[0].finalize_psbt(&mut psbt, signopts).unwrap();
    assert_eq!(
        count_signatures(&psbt),
        (0, num_inp.pow(count_mult.0), (num_inp - 1) * count_mult.1)
    );
    assert!(finalized);

    let spendable = wallets[0].verify_proof(&psbt, message, None)?;
    let balance = wallets[0].balance();
    assert!(
        spendable <= balance.confirmed,
        "spendable ({}) <= balance.confirmed ({})",
        spendable,
        balance.confirmed,
    );

    Ok(())
}

fn signer_from_priv(prvk: PrivateKey, pubk: PublicKey) -> Signer {
    let mut keymap = KeyMap::new();

    let pubk = DescriptorPublicKey::Single(SinglePub {
        origin: None,
        key: SinglePubKey::FullKey(pubk),
    });
    let prvk = DescriptorSecretKey::Single(SinglePriv {
        //let prvk = KeyMap::V::Single(SinglePriv {
        origin: None,
        key: prvk,
    });
    keymap.insert(pubk, prvk);

    Signer(keymap)
}
