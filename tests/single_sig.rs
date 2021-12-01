use bdk::wallet::get_funded_wallet;
use bdk::SignOptions;
use bdk_reserves::reserves::*;
use rstest::rstest;

#[rstest]
#[case("wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)")]
#[case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))")] // and(pk(Alice),older(6))
#[case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))")] // and(pk(Alice),after(100000))
fn test_proof(#[case] descriptor: &'static str) -> Result<(), ProofError> {
    let (wallet, _, _) = get_funded_wallet(descriptor);
    let balance = wallet.get_balance()?;

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(&message)?;
    let num_inp = psbt.inputs.len();
    assert!(
        num_inp > 1,
        "num_inp is {} but should be more than 1",
        num_inp
    );

    let finalized = wallet.sign(
        &mut psbt,
        SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        },
    )?;
    let num_sigs = psbt
        .inputs
        .iter()
        .fold(0, |acc, i| acc + i.partial_sigs.len());
    assert_eq!(num_sigs, num_inp - 1);
    assert!(finalized);

    let spendable = wallet.verify_proof(&psbt, &message, None)?;
    assert_eq!(spendable, balance);

    Ok(())
}
