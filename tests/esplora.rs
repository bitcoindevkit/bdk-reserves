#[cfg(feature = "esplora")]
use bdk_reserves::reserves::*;
#[cfg(feature = "esplora")]
use bdk_wallet::bitcoin::{
    Amount,
    base64::{Engine as _, engine::general_purpose::STANDARD},
    psbt::Psbt,
};
#[cfg(feature = "esplora")]
use chrono::{Datelike, Local};

#[cfg(feature = "esplora")]
#[tokio::test]
async fn test_esplora_active() {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    let psbt = include_str!("data/active.psbt").trim_end().to_string();
    let psbt = decode_tx(&psbt);
    assert_eq!(psbt.unsigned_tx.input.len(), 20);

    let message = "Stored in AMINA Bank AG cold storage";
    let pres = verify_proof_online(&psbt, message, "https://blockstream.info/testnet/api/")
        .await
        .unwrap();

    assert_eq!(pres.value, Amount::from_sat(922_739));
    assert_eq!(pres.timestamp.year(), Local::now().year());
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

    let message = "Stored in SEBA Bank AG cold storage";
    let pres = verify_proof_online(&psbt, message, "https://blockstream.info/testnet/api/")
        .await
        .unwrap();

    assert_eq!(pres.value, Amount::from_sat(53_865_580));
    assert_eq!(format!("{:?}", pres.timestamp), "2021-12-23T12:48:12Z");
}

#[cfg(feature = "esplora")]
/// Decodes a partially signed transaction from a base64 string.
pub fn decode_tx(tx: &str) -> Psbt {
    let tx = STANDARD.decode(tx).unwrap();
    Psbt::deserialize(tx.as_slice()).unwrap()
}
