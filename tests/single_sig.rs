use bdk_reserves::reserves::*;
use bdk_wallet::SignOptions;
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::test_utils::get_funded_wallet_single;
use rstest::rstest;

#[rstest]
#[case("wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)")]
#[case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))")] // and(pk(Alice),older(6))
#[case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))")] // and(pk(Alice),after(100000))
fn test_proof_singlesig(#[case] descriptor: &'static str) -> Result<(), ProofError> {
    let (mut wallet, _) = get_funded_wallet_single(descriptor);
    let balance = wallet.balance();

    let message = "This belongs to me.";
    let mut psbt = wallet.create_proof(message)?;
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
            //remove_partial_sigs: false,
            ..Default::default()
        },
    )?;

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
    assert_eq!(count_signatures(&psbt), (0, 1, 1));
    assert!(finalized);

    let spendable = wallet.verify_proof(&psbt, message, None)?;
    assert_eq!(spendable, balance.confirmed);

    Ok(())
}
