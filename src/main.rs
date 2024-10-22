extern crate sha2;
extern crate rand;


use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use rsa::{PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug,Clone)]
struct Transaction {
    sender: String,
    receiver: String,
    amount: u64,
    signature: Vec<u8>,
}

impl Transaction {
    fn new(sender: &RsaPrivateKey, receiver: String, amount: u64) -> Self {
        let sender_public_key = sender.to_public_key();
        let sender_key_str = base64::encode(sender_public_key.n().to_bytes_be());
        let transaction_data = format!("{}{}{}", sender_key_str, receiver, amount);

        let hashed_data = Sha256::digest(transaction_data.as_bytes());
        let padding = PaddingScheme::new_pkcs1v15_sign(None);
        let signature = sender.sign(padding, &hashed_data).unwrap();
        
        Transaction {
            sender: sender_key_str,
            receiver,
            amount,
            signature,
        }
    }

    fn verify(&self, public_key: &RsaPublicKey) -> bool {
        let transaction_data = format!("{}{}{}", self.sender, self.receiver, self.amount);
        let padding = PaddingScheme::new_pkcs1v15_sign(None);
        public_key.verify(
            padding,
            &Sha256::digest(transaction_data.as_bytes()),
            &self.signature,
        ).is_ok()
    }
}

#[derive(Debug)]
struct Block {
    index: u64,
    timestamp: u128,
    previous_hash: String,
    hash: String,
    nonce: u64,
    transactions: Vec<Transaction>,
}

impl Block {
    fn new(index: u64, previous_hash: String, transactions: Vec<Transaction>, difficulty: usize) -> Block {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let hash = String::new();
        let nonce = 0;
        let mut block = Block { 
            index,
            timestamp,
            previous_hash,
            hash,
            nonce,
            transactions,
        };
        block.hash = block.calculate_hash();
        block.mine_block(difficulty);
        block
    }

    fn calculate_hash(&self) -> String {
        let input = format!("{}{}{}{}", self.index, self.timestamp, self.previous_hash, self.nonce);
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }

    fn mine_block(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        while &self.hash[..difficulty] != target {
            self.nonce += 1;
            self.hash = self.calculate_hash();
        }
        println!("Block mined! Hash: {}", self.hash);
    }
}

#[derive(Debug)]
struct Blockchain {
    chain: Vec<Block>,
    difficulty: usize,
    pending_transactions: Vec<Transaction>,
    mining_reward: u64,
    balances: HashMap<String, u64>, // Track wallet balances
}

impl Blockchain {
    fn new(difficulty: usize, mining_reward: u64) -> Self {
        let mut blockchain = Blockchain {
            chain: vec![],
            difficulty,
            pending_transactions: vec![],
            mining_reward,
            balances: HashMap::new(),
        };
        blockchain.create_genesis_block();
        blockchain
    }

    fn create_genesis_block(&mut self) {
        let genesis_block = Block::new(0, String::from("0"), vec![], self.difficulty);
        self.chain.push(genesis_block);
    }

    fn get_latest_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    fn create_transaction(&mut self, transaction: Transaction,sender_public_key:&RsaPublicKey) {
        // Ensure sender has enough balance
        let sender_balance = *self.balances.get(&transaction.sender).unwrap_or(&0);
        if transaction.verify(sender_public_key){
         if sender_balance >= transaction.amount {
            self.pending_transactions.push(transaction);
        } else {
            println!("Transaction failed: insufficient balance");
        }
        }else{
            println!("Transaction failed: invalid signature")
        }
      
    }

  fn mine_pending_transactions(&mut self, miner_address: String) {
    let previous_hash = self.get_latest_block().hash.clone();
    
    // Add transactions to the block
    let new_block = Block::new(self.chain.len() as u64, previous_hash, self.pending_transactions.clone(), self.difficulty);

    // Display the transactions for this block (to use the transactions field)
    println!("Block {} contains the following transactions:", new_block.index);
    for transaction in &new_block.transactions {
        println!("{:?}", transaction);
    }

    // Add the new block to the chain
    self.chain.push(new_block);

    // Update balances for transactions in the block
    for transaction in &self.pending_transactions {
        // Deduct from the sender
        if let Some(sender_balance) = self.balances.get_mut(&transaction.sender) {
            *sender_balance -= transaction.amount;
        }

        // Add to the receiver
        self.balances.entry(transaction.receiver.clone()).or_insert(0);
        *self.balances.get_mut(&transaction.receiver).unwrap() += transaction.amount;
    }

    // Reward the miner
    self.balances.entry(miner_address.clone()).or_insert(0);
    *self.balances.get_mut(&miner_address).unwrap() += self.mining_reward;

    // Clear pending transactions
    self.pending_transactions.clear();
}
 fn display_chain(&self) {
        for block in &self.chain {
            println!("Block {} has the following transactions:", block.index);
            for transaction in &block.transactions {
                println!("{:?}", transaction);
            }
        }
    }

}

#[derive(Debug)]
struct Wallet {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl Wallet {
    fn new() -> Self {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        Wallet { private_key, public_key }
    }

    fn get_public_key(&self) -> String {
        base64::encode(self.public_key.n().to_bytes_be())
    }
}

fn main() {
    let difficulty = 4;
    let mining_reward = 50;

    // Create blockchain
    let mut blockchain = Blockchain::new(difficulty, mining_reward);

    // Create two wallets
    let wallet1 = Wallet::new();
    let wallet2 = Wallet::new();

    // Create and process a transaction
    let transaction = Transaction::new(&wallet1.private_key, wallet2.get_public_key(), 10);
 blockchain.create_transaction(transaction, &wallet1.public_key);

    // Mine pending transactions and reward miner
    blockchain.mine_pending_transactions(wallet1.get_public_key());

    // Check wallet balances
    println!("Wallet1 balance: {}", blockchain.balances.get(&wallet1.get_public_key()).unwrap_or(&0));
    println!("Wallet2 balance: {}", blockchain.balances.get(&wallet2.get_public_key()).unwrap_or(&0));
    // Display the chain with transactions
blockchain.display_chain();
}
