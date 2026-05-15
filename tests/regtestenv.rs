use bdk_electrum::electrum_client::Client;
use bdk_electrum::{BdkElectrumClient, electrum_client};
use bdk_wallet::bitcoin::{Amount, FeeRate};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use electrsd::ElectrsD;
use electrsd::bitcoind::BitcoinD;
use electrsd::bitcoind::client::bitcoin::{Address, Network};
use electrsd::electrum_client::ElectrumApi;
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

    /// generates a couple of blocks to have some coins to test with
    pub fn generate(&self, wallets: &mut [&mut Wallet]) {
        let addr2 = wallets[0].peek_address(KeychainKind::External, 1);
        let addr1 = wallets[0].peek_address(KeychainKind::External, 0);
        const MY_FOREIGN_ADDR: &str = "mpSFfNURcFTz2yJxBzRY9NhnozxeJ2AUC8";
        let foreign_addr = Address::from_str(MY_FOREIGN_ADDR)
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        // generate to the first receiving address of the test wallet
        self.generate_to_address(10, &addr2.address);
        // make the newly mined coins spendable
        self.generate_to_address(100, &foreign_addr);

        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(electrum_client::Client::new(self.electrum_url()).unwrap());

        const STOP_GAP: usize = 10;
        const BATCH_SIZE: usize = 5;
        wallets.iter_mut().enumerate().for_each(|(i, wallet)| {
            let full_scan_request = wallet.start_full_scan();
            let update = client
                .full_scan(full_scan_request, STOP_GAP, BATCH_SIZE, true)
                .unwrap();
            wallet.apply_update(update).unwrap();

            let balance = wallet.balance();
            assert!(
                balance.confirmed == Amount::from_int_btc(500),
                "balance of wallet {} is {} but should be 50_000_000_000",
                i,
                balance
            );
        });

        let mut builder = wallets[0].build_tx();
        builder
            .add_recipient(addr1.address.script_pubkey(), Amount::from_sat(1_000_000))
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
        let mut psbt = builder.finish().unwrap();
        let signopts = SignOptions {
            ..Default::default()
        };
        let finalized = wallets
            .iter_mut()
            .any(|wallet| wallet.sign(&mut psbt, signopts.clone()).unwrap());
        assert!(finalized);
        client
            .transaction_broadcast(&psbt.extract_tx().unwrap())
            .unwrap();

        // make the newly moved coins spendable
        self.generate_to_address(6, &foreign_addr);

        wallets.iter_mut().for_each(|wallet| {
            let sync_req = wallet.start_sync_with_revealed_spks().build();
            let update = client.sync(sync_req, BATCH_SIZE, true).unwrap();
            wallet.apply_update(update).unwrap();
        });
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
            .generate_to_address(blocks, address)
            .unwrap();

        let header = loop {
            std::thread::sleep(Duration::from_secs(1));
            let header = self.electrsd.client.block_headers_subscribe().unwrap();
            if header.height >= old_height + blocks {
                break header;
            }
        };

        assert!(
            header.height >= old_height + blocks,
            "{} >= {}",
            header.height,
            old_height + blocks
        );
    }
}

impl Default for RegTestEnv {
    fn default() -> Self {
        Self::new()
    }
}
