// 1. UTXO Model (Unspent Transaction Output)
// What is UTXO?: In a UTXO-based cryptocurrency, each transaction consumes previous outputs (spending the unspent transaction outputs) and creates new outputs. These outputs are available for future transactions until they are spent.
// UTXO Structure: Each transaction output is associated with a value and the recipient’s public key (address). UTXOs can only be spent by the recipient by creating a new transaction.
// 2. Peer-to-Peer Networking
// What is P2P Networking?: In a P2P network, nodes (peers) can connect with each other and exchange messages, such as broadcasting new blocks and transactions.
// P2P Protocol: We'll simulate a basic P2P network where nodes broadcast transactions and blocks to each other.
extern crate sha2;
extern crate rsa;
extern crate rand;

use sha2::{Sha256, Digest};
use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme,PublicKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use rsa::PublicKeyParts;
use std::time::{SystemTime, UNIX_EPOCH};
use rsa::pkcs1::DecodeRsaPublicKey; // For PKCS1 public key decoding

// Transaction Input
#[derive(Debug, Clone)]
struct TxInput {
    prev_tx: String,   // Hash of the previous transaction
    index: usize,      // Index of the output in the previous transaction
    signature: Vec<u8>, // Signature to prove ownership
}

// Transaction Output (UTXO)
#[derive(Debug, Clone)]
struct TxOutput {
    amount: u64,           // Amount of the coin
    recipient: String,     // Public key of the recipient
}

// Transaction structure
#[derive(Debug)]
struct Transaction {
    inputs: Vec<TxInput>,     // List of inputs (consuming previous UTXOs)
    outputs: Vec<TxOutput>,   // List of outputs (creating new UTXOs)
}

impl Transaction {
    // Function to create a new transaction and sign inputs
    fn new(sender: &RsaPrivateKey, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        // Each input must be signed by the sender's private key
        let mut signed_inputs = vec![];
        for mut input in inputs {
            let tx_data = format!("{}{}", input.prev_tx, input.index);
            let padding = PaddingScheme::new_pkcs1v15_sign(None);
            input.signature = sender.sign(padding, &Sha256::digest(tx_data.as_bytes()), ).unwrap();
            signed_inputs.push(input);
        }

        Transaction {
            inputs: signed_inputs,
            outputs,
        }
    }

    // Function to verify the transaction's inputs
    fn verify(&self, utxo_pool: &UTXOPool) -> bool {
        for input in &self.inputs {
            let prev_output = utxo_pool.get_utxo(&input.prev_tx, input.index);
            if prev_output.is_none() {
                return false;
            }
            let prev_output = prev_output.unwrap();

            // Decode the recipient's public key from base64 and PKCS1 format
            let recipient_public_key_bytes = base64::decode(&prev_output.recipient).unwrap();
            let recipient_public_key = RsaPublicKey::from_pkcs1_der(&recipient_public_key_bytes).unwrap();

            // Verify that the input signature matches the owner's public key
            let tx_data = format!("{}{}", input.prev_tx, input.index);
            let padding = PaddingScheme::new_pkcs1v15_sign(None);
          if recipient_public_key.verify(padding, &Sha256::digest(tx_data.as_bytes()), &input.signature).is_err() {
                return false;
            }
        }
        true
    }
}

// Block structure
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
        let hash = String::new();  // Start with an empty hash
        let nonce = 0;  // Start with a nonce of 0
        let mut block = Block { index, timestamp, previous_hash, hash, nonce, transactions };
        
        block.hash = block.calculate_hash();
        block.mine_block(difficulty);
        block
    }

    // Function to calculate the hash of the block
    fn calculate_hash(&self) -> String {
        let input = format!(
            "{}{}{}{}",
            self.index,
            self.timestamp,
            self.previous_hash,
            self.nonce
        );
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }

    // Function to mine the block (i.e., find a hash that meets the difficulty requirement)
    fn mine_block(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);  // The target hash must have `difficulty` number of leading zeros
        
        while &self.hash[..difficulty] != target {
            self.nonce += 1;
            self.hash = self.calculate_hash();
        }
        
        println!("Block mined! Hash: {}", self.hash);
    }
}

// UTXO Pool to manage unspent transaction outputs
struct UTXOPool {
    pool: HashMap<String, Vec<TxOutput>>,
}

impl UTXOPool {
    // Create a new UTXO pool
    fn new() -> Self {
        UTXOPool {
            pool: HashMap::new(),
        }
    }

    // Add a new transaction to the UTXO pool
    fn add_transaction(&mut self, tx_hash: String, outputs: Vec<TxOutput>) {
        self.pool.insert(tx_hash, outputs);
    }

    // Get a UTXO by its transaction hash and index
    fn get_utxo(&self, tx_hash: &String, index: usize) -> Option<&TxOutput> {
        self.pool.get(tx_hash).and_then(|outputs| outputs.get(index))
    }

    // Remove UTXOs that have been spent
    fn remove_spent_utxos(&mut self, inputs: &Vec<TxInput>) {
        for input in inputs {
            if let Some(outputs) = self.pool.get_mut(&input.prev_tx) {
                outputs.remove(input.index);
                if outputs.is_empty() {
                    self.pool.remove(&input.prev_tx);
                }
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
    fn new()->Self{
let mut rng = OsRng;
 let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
   let public_key = private_key.to_public_key();
    Wallet { private_key, public_key }
    }
     // Function to get the public key of the wallet (the account address)
    fn get_public_key(&self) -> String {
        base64::encode(self.public_key.n().to_bytes_be()) 
    }
}
fn main() {
    let difficulty = 4;

    // Create a UTXO pool to manage all unspent outputs
    let mut utxo_pool = UTXOPool::new();

    // Create two wallets
    let wallet1 = Wallet::new();
    let wallet2 = Wallet::new();

    // Create a transaction from wallet1 to wallet2 using UTXOs
    let initial_output = TxOutput { amount: 100, recipient: wallet1.get_public_key() };
    let genesis_tx = Transaction { inputs: vec![], outputs: vec![initial_output.clone()] };
    utxo_pool.add_transaction("genesis".to_string(), vec![initial_output]);

    let tx_input = TxInput { prev_tx: "genesis".to_string(), index: 0, signature: vec![] };
    let tx_output = TxOutput { amount: 50, recipient: wallet2.get_public_key() };
    let transaction = Transaction::new(&wallet1.private_key, vec![tx_input], vec![tx_output.clone()]);

    // Verify the transaction and update the UTXO pool
    if transaction.verify(&utxo_pool) {
        utxo_pool.add_transaction("tx1".to_string(), vec![tx_output]);
        utxo_pool.remove_spent_utxos(&transaction.inputs);
    }

    // Create a genesis block with this transaction
    let genesis_block = Block::new(0, String::from("0"), vec![genesis_tx], difficulty);
    println!("{:?}", genesis_block);

    // Create a new block linked to the genesis block with another transaction
    let tx_input2 = TxInput { prev_tx: "tx1".to_string(), index: 0, signature: vec![] };
    let tx_output2 = TxOutput { amount: 20, recipient: wallet1.get_public_key() };
    let new_transaction = Transaction::new(&wallet2.private_key, vec![tx_input2], vec![tx_output2]);
    let new_block = Block::new(1, genesis_block.hash, vec![new_transaction], difficulty);
    println!("{:?}", new_block);
}
