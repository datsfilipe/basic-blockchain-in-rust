use sha2::{Digest, Sha256};
use ed25519_compact::*;
use rand::*;
use std::{collections::HashMap, time::SystemTime, cell::RefCell, fmt::{Display, Formatter, Result}};

#[derive(Debug)]
#[allow(dead_code)]
struct Transaction {
    pub amount: u64,
    pub from: PublicKey,
    pub to: PublicKey
}

impl Transaction {
    pub fn new(
        amount: u64,
        from: PublicKey,
        to: PublicKey
    ) -> Transaction {
        Transaction {
            amount,
            from,
            to
        }
    }
}

type Hash = [u8; 32];

#[derive(Debug)]
#[allow(dead_code)]
struct Block {
    pub nonce: u32,
    pub prev_hash: Hash,
    pub tx: Transaction,
    pub ts: SystemTime
}

impl Block {
    pub fn new(
        prev_hash: Hash,
        tx: Transaction,
    ) -> Block {
        Block {
            nonce: random::<u32>(),
            prev_hash,
            tx,
            ts: SystemTime::now()
        }
    }

    pub fn get_hash(&self) -> Hash {
        let str = format!("{:?}", self); // Convert Block to string for hashing
        let mut hasher = Sha256::new();
        hasher.update(&str);
        hasher.finalize().into()
    }
}

impl<'a> Display for Chain {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for block in &self.chain {
            writeln!(f, "Nonce: {}", block.nonce)?;
            writeln!(f, "Previous Hash: {:?}", hex::encode(block.prev_hash))?;
            writeln!(f, "Transaction Amount: {}", block.tx.amount)?;
            writeln!(f, "Transaction From: {:?}", block.tx.from)?;
            writeln!(f, "Transaction To: {:?}", block.tx.to)?;
            writeln!(f, "Timestamp: {:?}", block.ts)?;
            writeln!(f, "---------------------------------")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ChainWallet {
    address: String,
    balance: u64
}

#[derive(Debug)]
struct ChainWallets {
    pub wallets: HashMap<String, ChainWallet>
}

#[derive(Debug)]
struct Chain {
    pub chain: Vec<Block>,
    pub wallets: Option<ChainWallets>
}

impl Chain {
    pub fn new() -> Chain {
        let mut chain = Vec::new();

        chain.push(
            Block::new(
                [0u8; 32],
                Transaction::new(100, new_public_key(), new_public_key())
            )
        );

        Chain {
            chain,
            wallets: None
        }
    }

    pub fn last_block(&self) -> &Block {
        &self.chain[self.chain.len() - 1]
    }

    pub fn mine(nonce: u32) -> u32 {
        let mut solution = 1;
        println!("Mining...");
        loop {
            let sum = nonce + solution;
            let hash = md5::compute(sum.to_le_bytes().to_vec());
            let attempt = format!("{:x}", hash);
            if attempt.starts_with("0000") {
                println!("Solved: {:x}", &solution);
                break;
            }

            solution += 1;
        }

        solution
    }


    pub fn check_wallet_funds(&self, sender_pub_key: PublicKey, tx_amount: u64) -> bool {
        let sender_balance = Wallet::get_balance_by_pub_key(sender_pub_key);
        if sender_balance < tx_amount {
            println!("Insufficient funds");
            false
        } else {
            true
        }
    }

    pub fn update_wallet_balance(&mut self, pub_key: PublicKey, tx_amount: u64, operation: bool) {
        let balance = Wallet::get_balance_by_pub_key(pub_key);

        if operation {
            Wallet::update_balance_by_pub_key(pub_key, balance + tx_amount);
        } else {
            Wallet::update_balance_by_pub_key(pub_key, balance - tx_amount);
        }
    }

    pub fn add_block(&mut self, tx: Transaction, sender_pub_key: PublicKey, signature: Signature) {
        let tx_hash: Hash = {
            let mut hasher = Sha256::new();
            hasher.update(&format!("{:?}", tx));
            hasher.finalize().into()
        };

        if let Ok(_) = sender_pub_key.verify(&tx_hash, &signature) {
            let last_hash = self.last_block().get_hash();
            let tx_amount = tx.amount;
            let receiver_pub_key = tx.to;

            let new_block = Block::new(
                last_hash,
                tx
            );

            if self.check_wallet_funds(sender_pub_key, tx_amount) == false {
                return;
            }

            Chain::mine(new_block.nonce);
            self.chain.push(new_block);
            self.update_wallet_balance(sender_pub_key, tx_amount, false);
            self.update_wallet_balance(receiver_pub_key, tx_amount, true);
        } else {
            println!("Transaction failed to verify");
        }
    }

    pub fn connect_wallet(&mut self, wallet: ChainWallet) {
        if let Some(wallets) = &mut self.wallets {
            wallets.wallets.insert(wallet.address.clone(), ChainWallet {
                address: wallet.address.clone(),
                balance: wallet.balance
            });
        } else {
            let mut wallets = HashMap::new();
            wallets.insert(wallet.address.clone(), ChainWallet {
                address: wallet.address.clone(),
                balance: wallet.balance
            });

            self.wallets = Some(ChainWallets {
                wallets
            });
        }
    }

    pub fn instance() -> &'static mut Chain {
        static mut CHAIN: Option<&'static RefCell<Chain>> = None;
        unsafe {
            if let Some(chain) = CHAIN {
                // Dereference RefMut to obtain mutable reference to Chain
                let ptr = &mut *chain.as_ptr();
                &mut *ptr
            } else {
                let chain = RefCell::new(Chain::new());
                CHAIN = Some(Box::leak(Box::new(chain)));
                // Dereference RefMut to obtain mutable reference to Chain
                let ptr = &mut *CHAIN.unwrap().as_ptr();
                &mut *ptr
            }
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct Wallet {
    pub address: String,
    pub pub_key: PublicKey,
    pub priv_key: SecretKey,
    pub balance: u64
}

impl Wallet {
    pub fn new(balance: u64) -> Wallet {
        let key_pair = KeyPair::from_seed(Seed::generate());

        let mut hasher = Sha256::new();
        hasher.update(&format!("{:?}", key_pair.pk));
        let hash = hasher.finalize();
        let address = format!("0x{}", hex::encode(hash));

        let chain = Chain::instance();
        chain.connect_wallet(ChainWallet {
            address: address.clone(),
            balance
        });

        Wallet {
            pub_key: key_pair.pk,
            priv_key: key_pair.sk,
            address,
            balance
        }
    }

    pub fn get_balance_by_pub_key(pub_key: PublicKey) -> u64 {
        let chain = Chain::instance();
        if let Some(wallets) = &chain.wallets {
            let mut hasher = Sha256::new();
            hasher.update(&format!("{:?}", pub_key));
            let address = format!("0x{}", hex::encode(hasher.finalize()));

            if let Some(wallet) = wallets.wallets.get(&address) {
                wallet.balance
            } else {
                0
            }
        } else {
            0
        }
    }

    pub fn update_balance_by_pub_key(pub_key: PublicKey, balance: u64) {
        let chain = Chain::instance();
        if let Some(wallets) = &mut chain.wallets {
            let mut hasher = Sha256::new();
            hasher.update(&format!("{:?}", pub_key));
            let address = format!("0x{}", hex::encode(hasher.finalize()));

            if let Some(wallet) = wallets.wallets.get_mut(&address) {
                wallet.balance = balance;
            }
        }
    }

    pub fn send(&mut self, amount: u64, sender_pub_key: PublicKey) {
        let tx = Transaction::new(amount, self.pub_key, sender_pub_key);
        let mut hasher = Sha256::new();
        hasher.update(&format!("{:?}", tx));
        let sign = hasher.finalize();

        let signature = self.priv_key.sign(&sign, None);
        let chain = Chain::instance();
        chain.add_block(tx, self.pub_key, signature);
    }
}

fn new_public_key() -> PublicKey {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    PublicKey::new(seed)
}

fn main() {
    let mut wallet1 = Wallet::new(100);
    let mut wallet2 = Wallet::new(300);
    let mut wallet3 = Wallet::new(300);

    wallet1.send(100, wallet2.pub_key);
    wallet2.send(200, wallet3.pub_key);
    wallet1.send(100, wallet2.pub_key); // Invalid transaction
    wallet3.send(100, wallet1.pub_key);

    println!("--------------");
    println!("- Blockchain -");
    println!("--------------");

    println!("{}", Chain::instance());
    println!("--------------");
    println!("Wallet 1 Balance: {}", Wallet::get_balance_by_pub_key(wallet1.pub_key));
    println!("Wallet 2 Balance: {}", Wallet::get_balance_by_pub_key(wallet2.pub_key));
    println!("Wallet 3 Balance: {}", Wallet::get_balance_by_pub_key(wallet3.pub_key));
}
