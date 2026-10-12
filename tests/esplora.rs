#[cfg(feature = "esplora")]
use bdk_reserves::reserves::*;
#[cfg(feature = "esplora")]
use bdk_wallet::bitcoin::{
    Amount,
    base64::{Engine as _, engine::general_purpose::STANDARD},
    psbt::Psbt,
};

#[cfg(feature = "esplora")]
#[tokio::test]
async fn test_esplora_active() {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    let psbt = include_str!("data/active.psbt").trim_end().to_string();
    let psbt = decode_tx(&psbt);
    assert_eq!(psbt.unsigned_tx.input.len(), 20);

    let outheight = verify_prevouts(&psbt, "https://blockstream.info/testnet/api/", None)
        .await
        .unwrap();
    assert_eq!(outheight.outpoints.len(), 20);
    assert!(
        outheight.unspent_height > 971104,
        "unspent_height ({}) > 971104",
        outheight.unspent_height
    );

    let message = "Stored in AMINA Bank AG cold storage";
    let amount = verify_proof(&psbt, message, outheight.outpoints).unwrap();
    assert_eq!(amount, Amount::from_sat(922_739));
}

#[cfg(feature = "esplora")]
#[tokio::test]
async fn test_esplora_spent() {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    let psbt = include_str!("data/spent.psbt").trim_end().to_string();
    let psbt = decode_tx(&psbt);
    assert_eq!(psbt.unsigned_tx.input.len(), 19);

    let outheight = verify_prevouts(&psbt, "https://blockstream.info/testnet/api/", None)
        .await
        .unwrap();
    assert_eq!(outheight.outpoints.len(), 19);
    assert_eq!(outheight.unspent_height, 2133038);

    let message = "Stored in SEBA Bank AG cold storage";
    let amount = verify_proof(&psbt, message, outheight.outpoints).unwrap();
    assert_eq!(amount, Amount::from_sat(53_865_580));
}

#[cfg(feature = "esplora")]
/// Decodes a partially signed transaction from a base64 string.
pub fn decode_tx(tx: &str) -> Psbt {
    let tx = STANDARD.decode(tx).unwrap();
    Psbt::deserialize(tx.as_slice()).unwrap()
}
