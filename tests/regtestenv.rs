use bdk::blockchain::{electrum::ElectrumBlockchain, Blockchain};
use bdk::database::memory::MemoryDatabase;
use bdk::electrum_client::Client;
use bdk::electrum_client::ElectrumApi;
use bdk::wallet::{AddressIndex, SyncOptions, Wallet};
use bdk::SignOptions;
use electrsd::bitcoind::bitcoincore_rpc::{bitcoin::Address, RpcApi};
use electrsd::bitcoind::BitcoinD;
use electrsd::ElectrsD;
use std::str::FromStr;
use std::time::Duration;

/// The environment to run a single test, while many of them can run in parallel.
pub struct RegTestEnv {
    /// Instance of the bitcoin core daemon
    bitcoind: BitcoinD,
    /// Instance of the electrs electrum server
    electrsd: ElectrsD,
}

impl RegTestEnv {
    /// set up local bitcoind and electrs instances in regtest mode
    pub fn new() -> Self {
        let mut bitcoind_conf = electrsd::bitcoind::Conf::default();
        bitcoind_conf.p2p = electrsd::bitcoind::P2P::Yes;

        let bitcoind_exe = electrsd::bitcoind::downloaded_exe_path()
            .expect("We should always have downloaded path");
        let bitcoind = BitcoinD::with_conf(bitcoind_exe, &bitcoind_conf).unwrap();

        let mut elect_conf = electrsd::Conf::default();
        elect_conf.view_stderr = false; // setting this to true will lead to very verbose logging
        let elect_exe =
            electrsd::downloaded_exe_path().expect("We should always have downloaded path");
        let electrsd = ElectrsD::with_conf(elect_exe, &bitcoind, &elect_conf).unwrap();

        RegTestEnv { bitcoind, electrsd }
    }

    /// returns the URL where a client can connect to the embedded electrum server
    pub fn electrum_url(&self) -> &str {
        &self.electrsd.electrum_url
    }

    /// generates some blocks to have some coins to test with
    pub fn generate(&self, wallets: &[&Wallet<MemoryDatabase>]) {
        let addr2 = wallets[0].get_address(AddressIndex::Peek(1)).unwrap();
        let addr1 = wallets[0].get_address(AddressIndex::Peek(0)).unwrap();
        const MY_FOREIGN_ADDR: &str = "mpSFfNURcFTz2yJxBzRY9NhnozxeJ2AUC8";
        let foreign_addr = Address::from_str(MY_FOREIGN_ADDR).unwrap();

        // generate to the first receiving address of the test wallet
        self.generate_to_address(10, &addr2);
        // make the newly mined coins spendable
        self.generate_to_address(100, &foreign_addr);

        let client = Client::new(self.electrum_url()).unwrap();
        let blockchain = ElectrumBlockchain::from(client);
        wallets.iter().enumerate().for_each(|(i, wallet)| {
            wallet.sync(&blockchain, SyncOptions::default()).unwrap();
            let balance = wallet.get_balance().unwrap();
            assert!(
                balance.confirmed == 5_000_000_000,
                "balance of wallet {} is {} but should be 5'000'000'000",
                i,
                balance
            );
        });

        let mut builder = wallets[0].build_tx();
        builder
            .add_recipient(addr1.script_pubkey(), 1_000_000)
            .fee_rate(bdk::FeeRate::from_sat_per_vb(2.0));
        let (mut psbt, _) = builder.finish().unwrap();
        let signopts = SignOptions {
            ..Default::default()
        };
        let finalized = wallets
            .iter()
            .any(|wallet| wallet.sign(&mut psbt, signopts.clone()).unwrap());
        assert!(finalized);
        blockchain.broadcast(&psbt.extract_tx()).unwrap();

        // make the newly moved coins spendable
        self.generate_to_address(6, &foreign_addr);

        wallets
            .iter()
            .for_each(|wallet| wallet.sync(&blockchain, SyncOptions::default()).unwrap());
    }

    fn generate_to_address(&self, blocks: usize, address: &Address) {
        let old_height = self
            .electrsd
            .client
            .block_headers_subscribe()
            .unwrap()
            .height;

        self.bitcoind
            .client
            .generate_to_address(blocks as u64, address)
            .unwrap();

        let header = loop {
            std::thread::sleep(Duration::from_secs(1));
            let header = self.electrsd.client.block_headers_subscribe().unwrap();
            if header.height >= old_height + blocks {
                break header;
            }
        };

        assert_eq!(header.height, old_height + blocks);
    }
}

impl Default for RegTestEnv {
    fn default() -> Self {
        Self::new()
    }
}
