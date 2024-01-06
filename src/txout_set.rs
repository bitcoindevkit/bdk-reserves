use bdk::bitcoin::{OutPoint, Transaction, Txid, TxOut};
use bdk::database::BatchDatabase;
use bdk::wallet::Wallet;

#[cfg(feature = "use-esplora-blocking" )]
use esplora_client::BlockingClient;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::iter::FromIterator;

/// Trait to look up `TxOut`s by `OutPoint`
pub trait TxOutSet {
    /// Lookup error return type
    type Error;

    /// Atomically look up txouts
    fn get_prevouts<'a, I: IntoIterator<Item=&'a OutPoint>, T: FromIterator<Option<TxOut>>>(&self, outpoints: I) -> Result<T, Self::Error>;
}

pub trait PointInTimeTxOutSet<'a> {
    type Target;

    fn txout_set_at_height(&'a self, height: u32) -> Self::Target;
}

impl<D> TxOutSet for &Wallet<D>
where
    D: BatchDatabase,
{
    type Error = bdk::Error;

    fn get_prevouts<'a, I: IntoIterator<Item=&'a OutPoint>, T: FromIterator<Option<TxOut>>>(&self, outpoints: I) -> Result<T, Self::Error> {
        let wallet_at_height = WalletAtHeight::new(self, u32::MAX);

        wallet_at_height.get_prevouts(outpoints)
    }
}

impl TxOutSet for &BTreeMap<OutPoint, TxOut> {
    type Error = ();

    fn get_prevouts<'a, I: IntoIterator<Item=&'a OutPoint>, T: FromIterator<Option<TxOut>>>(&self, outpoints: I) -> Result<T, Self::Error> {
        let iter = outpoints
            .into_iter()
            .map(|outpoint|
                self
                    .get(outpoint)
                    .map(|txout| txout.to_owned())
            );

        Ok(T::from_iter(iter))
    }
}

/// Adapter for a wallet to a TxOutSet at a particular block height
pub struct WalletAtHeight<'a, D>
where
    D: BatchDatabase
{
    wallet: &'a Wallet<D>,
    max_block_height: u32,
}

impl <'a, D> WalletAtHeight<'a, D>
where
    D: BatchDatabase
{
    pub fn new(wallet: &'a Wallet<D>, max_block_height: u32) -> Self {
        WalletAtHeight {
            wallet,
            max_block_height,
        }
    }
}

impl<'a, D> TxOutSet for WalletAtHeight<'a, D>
where
    D: BatchDatabase
{
    type Error = bdk::Error;

    fn get_prevouts<'b, I: IntoIterator<Item=&'b OutPoint>, T: FromIterator<Option<TxOut>>>(&self, outpoints: I) -> Result<T, Self::Error> {
        let outpoints: Vec<_> = outpoints
            .into_iter()
            .collect();

        let outpoint_set: BTreeSet<&OutPoint> = outpoints
            .iter()
            .map(|outpoint| *outpoint)
            .collect();

        let tx_heights: BTreeMap<_, _> = if self.max_block_height < u32::MAX {
            outpoint_set
                .iter()
                .map(|outpoint| {
                    let tx_details = match self.wallet.get_tx(&outpoint.txid, false)? {
                        Some(tx_details) => { tx_details },
                        None => { return Ok((outpoint.txid, None)); },
                    };

                    Ok((
                        outpoint.txid,
                        tx_details.confirmation_time
                            .map(|tx_details| tx_details.height)
                    ))
                })
                .filter_map(|result| match result {
                    Ok((txid, Some(height))) => { Some(Ok((txid, height))) },
                    Ok((_, None)) => { None },
                    Err(e) => {Some(Err(e)) },
                })
                .collect::<Result<_, Self::Error>>()?
        } else {
            // If max_block_height is u32::MAX, skip the potentially expensive tx detail lookup
            BTreeMap::new()
        };

        let unspent: BTreeMap<_, _> = self.wallet
            .list_unspent()?
            .into_iter()
            .filter_map(|output| {
                if outpoint_set.contains(&output.outpoint) {
                    let confirmation_height = tx_heights
                        .get(&output.outpoint.txid)
                        .unwrap_or(&u32::MAX);

                    if *confirmation_height <= self.max_block_height {
                        Some((output.outpoint, output.txout))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        let iter = outpoints
            .into_iter()
            .map(|outpoint|
                unspent
                    .get(outpoint)
                    .map(|outpoint| outpoint.to_owned())
            );

        Ok(T::from_iter(iter))
    }
}

#[cfg(feature = "use-esplora-blocking" )]
pub struct EsploraAtHeight<'a> {
    client: &'a BlockingClient,
    height: Option<u32>,
}

#[cfg(feature = "use-esplora-blocking" )]
impl<'a> EsploraAtHeight<'a> {
    pub fn new(client: &'a BlockingClient, height: Option<u32>) -> Self {
        Self {
            client,
            height,
        }
    }
}

#[cfg(feature = "use-esplora-blocking" )]
impl<'a> TxOutSet for EsploraAtHeight<'a> {
    type Error = esplora_client::Error;

    fn get_prevouts<'b, I: IntoIterator<Item=&'b OutPoint>, T: FromIterator<Option<TxOut>>>(&self, outpoints: I) -> Result<T, Self::Error> {
        let outpoints: Vec<_> = outpoints
            .into_iter()
            .collect();

        let input_txids: BTreeSet<Txid> = outpoints
            .iter()
            .map(|outpoint| outpoint.txid)
            .collect();

        let transactions: BTreeMap<&Txid, Transaction> = input_txids
            .iter()
            .filter_map(|txid| {
                let transaction = self.client.get_tx(txid)
                    .unwrap_or(None);

                let height = if self.height.is_some() {
                    self.client.get_tx_status(txid)
                        .map(|tx_status|
                             tx_status
                                .map(|tx_status| tx_status.block_height)
                                .unwrap_or(None)
                        )
                        .unwrap_or(None)
                } else {
                    None
                };

                match (self.height, height) {
                    (Some(_maximum_height), None) => {
                        None
                    },
                    (Some(maximum_height), Some(height)) if height > maximum_height => {
                        None
                    },
                    (None, Some(_height)) => {
                        None
                    },
                    _ => {
                        transaction.map(|transaction| (txid, transaction))
                    },
                }
            })
            .collect();

        let prevouts = outpoints
            .iter()
            .map(|outpoint| -> Result<Option<TxOut>, Self::Error> {
                let txout = transactions
                    .get(&outpoint.txid)
                    .and_then(|transaction|
                        transaction.output
                            .get(outpoint.vout as usize)
                    );

                let txout = if let Some(txout) = txout {
                    txout
                } else {
                    return Ok(None);
                };

                let txout_status = self.client
                    .get_output_status(&outpoint.txid, outpoint.vout as u64)?;

                if let Some(txout_status) = txout_status {
                    let spending_tx_height = txout_status.status
                        .map(|status| status.block_height)
                        .unwrap_or(None);

                    match (self.height, spending_tx_height) {
                        (Some(height), Some(spending_tx_height)) if height < spending_tx_height => { },
                        (_, Some(_spending_tx_height)) => {
                            return Ok(None);
                        },
                        (_, _) if txout_status.spent => {
                            return Ok(None);
                        },
                        _ => { },
                    };
                } else {
                    // FIXME: should we treat this as an error? or does this just mean it's not spent?
                }

                Ok(Some(txout.clone()))
            });

        Result::<T, Self::Error>::from_iter(prevouts)
    }
}

#[cfg(feature = "use-esplora-blocking" )]
impl<'a> PointInTimeTxOutSet<'a> for BlockingClient {
    type Target = EsploraAtHeight<'a>;

    fn txout_set_at_height(&'a self, height: u32) -> Self::Target {
        EsploraAtHeight { client: self, height: Some(height) }
    }
}

#[cfg(feature = "use-esplora-blocking" )]
impl<'a> TxOutSet for BlockingClient {
    type Error = esplora_client::Error;

    fn get_prevouts<'b, I: IntoIterator<Item=&'b OutPoint>, T: FromIterator<Option<TxOut>>>(&self, outpoints: I) -> Result<T, Self::Error> {
        let esplora_at_height = EsploraAtHeight { client: self, height: None };

        esplora_at_height.get_prevouts(outpoints)
    }
}

#[cfg(test)]
#[cfg(feature = "use-esplora-blocking" )]
mod test_esplora {
    use bdk::bitcoin::{OutPoint, Txid};
    use esplora_client::{BlockingClient, Builder};

    use std::iter::once;
    use std::str::FromStr;

    use crate::txout_set::PointInTimeTxOutSet;

    use super::TxOutSet;

    const ESPLORA_URL: &str = "https://mempool.space/signet/api";
    const TEST_TX_BLOCK_HEIGHT: u32 = 175435;

    fn get_client() -> BlockingClient {
        Builder::new(ESPLORA_URL)
            .build_blocking()
            .expect("build esplora client")
    }

    fn txid(s: &str) -> Txid {
        Txid::from_str(s)
            .expect("parse txid")
    }

    fn test_txid() -> Txid {
        Txid::from_str("52e318567fc09d7ab56e9861ea8cdd970964e64a83521da94d91adf51ded5da4")
            .expect("parse txid")
    }

    fn test_parent_txid() -> Txid {
        Txid::from_str("36e9be6467e4afe396de7a4fcbeca45e0bfaa0ea7d6344f769e5df7c80d088cb")
            .expect("parse txid")
    }

    #[test]
    pub fn test_esplora() {
        let client = get_client();

        client.get_height()
            .expect(&format!("problem with esplora \"{ESPLORA_URL}\""));
    }

    #[test]
    pub fn test_confirmed_unspent_at_tip() {
        let client = get_client();

        let outpoints = [
            OutPoint {
                txid: test_txid(),
                vout: 1,
            },
            // tx only has 3 outputs
            OutPoint {
                txid: test_txid(),
                vout: 4,
            },
        ];

        let prevouts: Vec<_> = client.get_prevouts(outpoints.iter())
            .expect("get prevouts");

        let valid_prevout = prevouts[0].as_ref().unwrap();
        assert!(valid_prevout.value == 699828);
        assert!(prevouts[1].is_none());
    }

    #[test]
    pub fn test_confirmed_at_height() {
        let client = get_client();

        let txouts = client.txout_set_at_height(TEST_TX_BLOCK_HEIGHT);

        let outpoints = [
            OutPoint {
                txid: test_txid(),
                vout: 1,
            },
        ];

        let prevouts: Vec<_> = txouts.get_prevouts(outpoints.iter())
            .expect("get prevouts");

        assert!(prevouts[0].is_some());
    }

    #[test]
    pub fn test_not_confirmed_at_height() {
        let client = get_client();

        let txouts = client.txout_set_at_height(TEST_TX_BLOCK_HEIGHT - 1);

        let outpoints = [
            OutPoint {
                txid: test_txid(),
                vout: 1,
            },
        ];

        let prevouts: Vec<_> = txouts.get_prevouts(outpoints.iter())
            .expect("get prevouts");

        assert!(prevouts[0].is_none());
    }

    #[test]
    pub fn test_spent_at_later_height() {
        let client = get_client();

        let txouts = client.txout_set_at_height(TEST_TX_BLOCK_HEIGHT - 1);

        let outpoints = [
            OutPoint {
                txid: test_parent_txid(),
                vout: 0,
            },
        ];

        let prevouts: Vec<_> = txouts.get_prevouts(outpoints.iter())
            .expect("get prevouts");

        assert!(prevouts[0].is_some());
    }
}
