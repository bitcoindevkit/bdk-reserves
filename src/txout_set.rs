use bdk::bitcoin::{OutPoint, TxOut};
#[cfg(any(feature = "electrum", feature = "use-esplora-blocking"))]
use bdk::bitcoin::{Transaction, Txid};
use bdk::database::BatchDatabase;
use bdk::wallet::Wallet;

#[cfg(feature = "electrum")]
use electrum_client::{Client as ElectrumClient, ElectrumApi};

#[cfg(feature = "use-esplora-blocking")]
use esplora_client::BlockingClient as EsploraClient;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::iter::FromIterator;

/// Trait to look up `TxOut`s by `OutPoint`
pub trait TxOutSet {
    /// Lookup error return type
    type Error;

    /// Atomically look up txouts
    fn get_prevouts<'a, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'a OutPoint>,
        T: FromIterator<Option<TxOut>>;
}

/// Trait to get the current UTXO set at the tip of the blockchain
pub trait TipTxOutQuery<'a> {
    type Target;

    /// Get a TxOutSet representing the TxOutSet at the tip of the blockchain
    fn txout_set_at_tip(&'a self) -> Self::Target;
}

/// Trait to get a TxOutSet with a consistent view of the
/// blockchain at a given height
pub trait HistoricalTxOutQuery<'a> {
    type Target;

    /// Get a TxOutSet representing the actual TxOutSet at that block height.
    /// This permits an accurate historical snapshot of a point in time.
    fn txout_set_at_height(&'a self, height: u32) -> Self::Target;
}

/// Trait to get the current UTXO set, excluding UTXOs confirmed after a given
/// height, and also excluding UTXOs known to be spent since that height.
pub trait MaxHeightTxOutQuery<'a> {
    type Target;

    fn txout_set_confirmed_by_height(&'a self, height: u32) -> Self::Target;
}

impl<D> TxOutSet for &Wallet<D>
where
    D: BatchDatabase,
{
    type Error = bdk::Error;

    fn get_prevouts<'a, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'a OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        let wallet_at_height = self.txout_set_confirmed_by_height(u32::MAX);

        wallet_at_height.get_prevouts(outpoints)
    }
}

impl<'a, T: TxOutSet + 'a> TipTxOutQuery<'a> for T {
    type Target = &'a Self;

    fn txout_set_at_tip(&'a self) -> Self::Target {
        self
    }
}

impl<S: TxOutSet> TxOutSet for &S {
    type Error = <S as TxOutSet>::Error;

    fn get_prevouts<'a, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'a OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        (*self).get_prevouts(outpoints)
    }
}

impl TxOutSet for &BTreeMap<OutPoint, TxOut> {
    type Error = ();

    fn get_prevouts<'b, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'b OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        let iter = outpoints
            .into_iter()
            .map(|outpoint| self.get(outpoint).map(|txout| txout.to_owned()));

        Ok(T::from_iter(iter))
    }
}

/// Adapter for a wallet to a TxOutSet at a particular block height
pub struct WalletConfirmedByHeight<'a, D>
where
    D: BatchDatabase,
{
    wallet: &'a Wallet<D>,
    max_block_height: u32,
}

impl<'a, D> MaxHeightTxOutQuery<'a> for Wallet<D>
where
    D: BatchDatabase + 'a,
{
    type Target = WalletConfirmedByHeight<'a, D>;

    fn txout_set_confirmed_by_height(&'a self, height: u32) -> Self::Target {
        WalletConfirmedByHeight {
            wallet: self,
            max_block_height: height,
        }
    }
}

impl<'a, D> TxOutSet for WalletConfirmedByHeight<'a, D>
where
    D: BatchDatabase,
{
    type Error = bdk::Error;

    fn get_prevouts<'b, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'b OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        let outpoints: Vec<_> = outpoints.into_iter().collect();

        let outpoint_set: BTreeSet<&OutPoint> = outpoints.iter().copied().collect();

        let tx_heights: BTreeMap<_, _> = if self.max_block_height < u32::MAX {
            outpoint_set
                .iter()
                .map(|outpoint| {
                    let tx_details = match self.wallet.get_tx(&outpoint.txid, false)? {
                        Some(tx_details) => tx_details,
                        None => {
                            return Ok((outpoint.txid, None));
                        }
                    };

                    Ok((
                        outpoint.txid,
                        tx_details
                            .confirmation_time
                            .map(|tx_details| tx_details.height),
                    ))
                })
                .filter_map(|result| match result {
                    Ok((txid, Some(height))) => Some(Ok((txid, height))),
                    Ok((_, None)) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<_, Self::Error>>()?
        } else {
            // If max_block_height is u32::MAX, skip the potentially expensive tx detail lookup
            BTreeMap::new()
        };

        let unspent: BTreeMap<_, _> = self
            .wallet
            .list_unspent()?
            .into_iter()
            .filter_map(|output| {
                if outpoint_set.contains(&output.outpoint) {
                    let confirmation_height =
                        tx_heights.get(&output.outpoint.txid).unwrap_or(&u32::MAX);

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
            .map(|outpoint| unspent.get(outpoint).map(|outpoint| outpoint.to_owned()));

        Ok(T::from_iter(iter))
    }
}

#[cfg(feature = "electrum")]
pub struct ElectrumAtHeight<'a> {
    client: &'a ElectrumClient,
    maximum_txout_height: Option<u32>,
}

#[cfg(feature = "electrum")]
impl TxOutSet for ElectrumClient {
    type Error = electrum_client::Error;

    fn get_prevouts<'a, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'a OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        let electrum_at_height = ElectrumAtHeight {
            client: self,
            maximum_txout_height: None,
        };

        electrum_at_height.get_prevouts(outpoints)
    }
}

#[cfg(feature = "electrum")]
impl<'a> MaxHeightTxOutQuery<'a> for ElectrumClient {
    type Target = ElectrumAtHeight<'a>;

    fn txout_set_confirmed_by_height(&'a self, height: u32) -> Self::Target {
        ElectrumAtHeight {
            client: self,
            maximum_txout_height: Some(height),
        }
    }
}

#[cfg(feature = "electrum")]
impl<'a> TxOutSet for ElectrumAtHeight<'a> {
    type Error = electrum_client::Error;

    fn get_prevouts<'b, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'b OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        let outpoints: Vec<_> = outpoints.into_iter().collect();

        let input_txids: BTreeSet<Txid> = outpoints.iter().map(|outpoint| outpoint.txid).collect();

        // avoiding the obvious batch_transaction_get optimization because
        // I'm not sure how it handles cases where some transactions are present but not others
        // FIXME: Probably should retain some types of errors here
        // and report them later
        let transactions: BTreeMap<&Txid, Transaction> = input_txids
            .iter()
            .filter_map(|txid| {
                self.client
                    .transaction_get(txid)
                    .map(|tx| Some((txid, tx)))
                    .unwrap_or(None)
            })
            .collect();

        let iter = outpoints.iter().map(|outpoint| {
            let previous_tx = match transactions.get(&outpoint.txid) {
                Some(previous_tx) => previous_tx,
                None => {
                    return Ok(None);
                }
            };

            let output = match previous_tx.output.get(outpoint.vout as usize) {
                Some(output) => output,
                None => {
                    return Ok(None);
                }
            };

            let unspent = self.client.script_list_unspent(&output.script_pubkey)?;

            let output_in_unspent_list = unspent.iter().find(|unspent_info| {
                unspent_info.tx_hash == outpoint.txid
                    && unspent_info.tx_pos == outpoint.vout as usize
                    && unspent_info.height
                        <= (self.maximum_txout_height.unwrap_or(u32::MAX) as usize)
            });

            match output_in_unspent_list {
                Some(_) => Ok(Some(output.to_owned())),
                None => Ok(None),
            }
        });

        Result::<T, Self::Error>::from_iter(iter)
    }
}

#[cfg(feature = "use-esplora-blocking")]
pub struct EsploraAtHeight<'a> {
    client: &'a EsploraClient,
    height: Option<u32>,
}

#[cfg(feature = "use-esplora-blocking")]
impl<'a> EsploraAtHeight<'a> {
    pub fn new(client: &'a EsploraClient, height: Option<u32>) -> Self {
        Self { client, height }
    }
}

#[cfg(feature = "use-esplora-blocking")]
impl<'a> TxOutSet for EsploraAtHeight<'a> {
    type Error = esplora_client::Error;

    fn get_prevouts<'b, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'b OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        let outpoints: Vec<_> = outpoints.into_iter().collect();

        // Remove duplicate txids
        let input_txids: BTreeSet<Txid> = outpoints.iter().map(|outpoint| outpoint.txid).collect();

        let transactions: BTreeMap<&Txid, Transaction> = input_txids
            .iter()
            .filter_map(|txid| {
                let transaction = self.client.get_tx(txid).unwrap_or(None);

                // Get the block height of the input transaction if
                // this TxOutSet is restricted to a specific height.
                let height = if self.height.is_some() {
                    self.client
                        .get_tx_status(txid)
                        .map(|tx_status| {
                            tx_status
                                .map(|tx_status| tx_status.block_height)
                                .unwrap_or(None)
                        })
                        .unwrap_or(None)
                } else {
                    None
                };

                match (self.height, height) {
                    (None, Some(_height)) => None, //Should be unreachable really
                    (Some(_maximum_height), None) => None,
                    (Some(maximum_height), Some(height)) if height > maximum_height => None,
                    (Some(_maximum_height), Some(_height)) => {
                        transaction.map(|transaction| (txid, transaction))
                    }
                    (None, None) => transaction.map(|transaction| (txid, transaction)),
                }
            })
            .collect();

        let prevouts = outpoints
            .iter()
            .map(|outpoint| -> Result<Option<TxOut>, Self::Error> {
                let txout = transactions
                    .get(&outpoint.txid)
                    .and_then(|transaction| transaction.output.get(outpoint.vout as usize));

                let txout = if let Some(txout) = txout {
                    txout
                } else {
                    return Ok(None);
                };

                let txout_status = self
                    .client
                    .get_output_status(&outpoint.txid, outpoint.vout as u64)?;

                if let Some(txout_status) = txout_status {
                    let spending_tx_height = txout_status
                        .status
                        .map(|status| status.block_height)
                        .unwrap_or(None);

                    match (self.height, spending_tx_height) {
                        // Ignore spends at later/highre blo
                        (Some(height), Some(spending_tx_height)) if height < spending_tx_height => {
                        }
                        (_, Some(_spending_tx_height)) => {
                            return Ok(None);
                        }
                        (_, _) if txout_status.spent => {
                            return Ok(None);
                        }
                        _ => {}
                    };
                } else {
                    // Esplora will return a non-None result for all known transaction outputs.
                    // Since we've already retrieved the transaction, and confirmed the relevant
                    // output exists, this should be unreachable unless the esplora instance is
                    // broken or malicious. Returning a None is the best way I can see to handle
                    // this, as a panic would enable a malicious esplora instance to cause much
                    // greater trouble.
                    return Ok(None);
                }

                Ok(Some(txout.clone()))
            });

        Result::<T, Self::Error>::from_iter(prevouts)
    }
}

#[cfg(feature = "use-esplora-blocking")]
impl<'a> HistoricalTxOutQuery<'a> for EsploraClient {
    type Target = EsploraAtHeight<'a>;

    fn txout_set_at_height(&'a self, height: u32) -> Self::Target {
        EsploraAtHeight {
            client: self,
            height: Some(height),
        }
    }
}

#[cfg(feature = "use-esplora-blocking")]
impl<'a> TxOutSet for EsploraClient {
    type Error = esplora_client::Error;

    fn get_prevouts<'b, I, T>(&self, outpoints: I) -> Result<T, Self::Error>
    where
        I: IntoIterator<Item = &'b OutPoint>,
        T: FromIterator<Option<TxOut>>,
    {
        let esplora_at_height = EsploraAtHeight {
            client: self,
            height: None,
        };

        esplora_at_height.get_prevouts(outpoints)
    }
}
