// Import necessary crates for hashing (SHA-256), random number generation, and RSA encryption
extern crate sha2;
extern crate rand;

use rand::rngs::OsRng; // For random number generation using OS's random generator
use sha2::{Sha256, Digest}; // For SHA-256 hashing
use rsa::{PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey}; // For RSA keys and padding schemes
use std::collections::HashMap; // For storing balances using a hash map
use std::time::{SystemTime, UNIX_EPOCH}; // For timestamps
// use tokio::net::{TcpListener, TcpStream};
// use tokio::*;
// use serde::{Serialize, Deserialize};

// Struct representing a transaction between two parties
#[derive(Debug, Clone)]
struct Transaction { 
    sender: String, // Base64 encoded public key of the sender
    receiver: String, // Base64 encoded public key of the receiver
    amount: u64, // Amount being transferred
    signature: Vec<u8>, // Digital signature of the transaction
}

// Implementation of the Transaction struct
impl Transaction {
    // Constructor for creating a new transaction
    fn new(sender: &RsaPrivateKey, receiver: String, amount: u64) -> Self {
        // Convert sender's private key to public key and encode it
        let sender_public_key = sender.to_public_key();
        let sender_key_str = base64::encode(sender_public_key.n().to_bytes_be());
        
        // Create a string representation of the transaction data
        let transaction_data = format!("{}{}{}", sender_key_str, receiver, amount);
        
        // Hash the transaction data
        let hashed_data = Sha256::digest(transaction_data.as_bytes());
        
        // Create a padding scheme for signing the transaction
        let padding = PaddingScheme::new_pkcs1v15_sign(None);
        
        // Sign the hashed transaction data with the sender's private key
        let signature = sender.sign(padding, &hashed_data).unwrap();
        
        // Return a new Transaction object
        Transaction {
            sender: sender_key_str,
            receiver,
            amount,
            signature,
        }
    }

    fn id(&self) -> String {
        let transaction_data = format!("{}{}{}", self.sender, self.receiver, self.amount);
        let mut hasher = Sha256::new();
        hasher.update(transaction_data);
        format!("{:x}", hasher.finalize())
    }

    // Method to verify a transaction's signature
    fn verify(&self, public_key: &RsaPublicKey) -> bool {
        // Recreate the transaction data string for verification
        let transaction_data = format!("{}{}{}", self.sender, self.receiver, self.amount);
        
        // Create a padding scheme for verification
        let padding = PaddingScheme::new_pkcs1v15_sign(None);
        
        // Verify the signature using the public key
        public_key.verify(
            padding,
            &Sha256::digest(transaction_data.as_bytes()),
            &self.signature,
        ).is_ok() // Returns true if the verification is successful
    }
}

// Struct representing a block in the blockchain
#[derive(Debug)]
struct Block {
    index: u64, // Position of the block in the chain
    timestamp: u128, // Time the block was created
    previous_hash: String, // Hash of the previous block
    hash: String, // Current block's hash
    nonce: u64, // Number used for mining (proof of work)
    transactions: Vec<Transaction>, // Transactions included in the block
}

// Implementation of the Block struct
impl Block {
    // Constructor for creating a new block
    fn new(index: u64, previous_hash: String, transactions: Vec<Transaction>, difficulty: usize) -> Block {
        // Get current timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        
        // Initialize an empty hash and nonce
        let hash = String::new();
        let nonce = 0;
        
        // Create the block and calculate its hash
        let mut block = Block { 
            index,
            timestamp,
            previous_hash,
            hash,
            nonce,
            transactions,
        };
        block.hash = block.calculate_hash();
        block.mine_block(difficulty); // Mine the block to find a valid hash
        block
    }

    // Method to calculate the hash of the block
    fn calculate_hash(&self) -> String {
        // Create a string representation of the block's properties
        let input = format!("{}{}{}{}", self.index, self.timestamp, self.previous_hash, self.nonce);
        
        // Create a SHA-256 hasher and update it with the input
        let mut hasher = Sha256::new();
        hasher.update(input);
        
        // Return the calculated hash as a hexadecimal string
        format!("{:x}", hasher.finalize())
    }

    // Method to mine the block (find a valid hash based on difficulty)
    fn mine_block(&mut self, difficulty: usize) {
        // Create a target hash prefix based on difficulty (e.g., "0000" for difficulty 4)
        let target = "0".repeat(difficulty);
        
        // Keep incrementing nonce until a valid hash is found
        while &self.hash[..difficulty] != target {
            self.nonce += 1;
            self.hash = self.calculate_hash(); // Recalculate hash with the new nonce
        }
        println!("Block mined! Hash: {}", self.hash); // Output mined hash
    }
}
// UTXO (Unspent Transaction Output)
// The UTXO model keeps track of unspent outputs rather than maintaining account balances directly.
//  Each transaction consumes UTXOs as inputs and creates new UTXOs as outputs.
#[derive(Debug, Clone)]
struct UTXO {
    tx_id: String, // ID of the transaction that created this UTXO
    output_index: usize, // Output index in the transaction
    amount: u64, // Amount of this UTXO
    receiver: String, // Receiver of this UTXO
}


// Struct representing the blockchain itself
#[derive(Debug)]
struct Blockchain {
    chain: Vec<Block>, // List of blocks in the blockchain
    difficulty: usize, // Difficulty of mining
    pending_transactions: Vec<Transaction>, // Transactions waiting to be added to a block
    mining_reward: u64, // Reward given to miners
    balances: HashMap<String, u64>, // Track wallet balances
    total_mined: u64, // Total coins mined
    utxos: HashMap<String, Vec<UTXO>>, // Map of public keys to their UTXOs
}

// Define the total supply limit for the coin
const TOTAL_SUPPLY: u64 = 21_000_000; // Total limit of coins

// Implementation of the Blockchain struct
impl Blockchain {
    // Constructor for creating a new blockchain
    fn new(difficulty: usize, mining_reward: u64) -> Self {
        let mut blockchain = Blockchain {
            chain: vec![], // Initialize with an empty chain
            difficulty,
            pending_transactions: vec![], // Initialize with no pending transactions
            mining_reward,
            balances: HashMap::new(), // Initialize with no balances
            total_mined: 0, // Initialize total mined coins to zero
            utxos:HashMap::new(),
        };
        blockchain.create_genesis_block(); // Create the first block (genesis block)
        blockchain
    }

    // Method to create the genesis block
    fn create_genesis_block(&mut self) {
        // Create a block with index 0, no transactions, and a previous hash of "0"
        let genesis_block = Block::new(0, String::from("0"), vec![], self.difficulty);
        self.chain.push(genesis_block); // Add it to the chain
    }

    // Method to get the latest block in the chain
    fn get_latest_block(&self) -> &Block {
        self.chain.last().unwrap() // Return the last block
    }

    // Method to create and add a transaction to the pending transactions
    fn create_transaction(&mut self, transaction: Transaction, sender_public_key: &RsaPublicKey) {
        // Ensure the sender has enough balance to make the transaction
        let sender_balance = *self.balances.get(&transaction.sender).unwrap_or(&0);
        // let sender_utxos = self.utxos.get(&transaction.sender).unwrap();
        // let total_amount: u64 = sender_utxos.iter().map(|utxo| utxo.amount).sum();
        
        // Verify the transaction signature
        if transaction.verify(sender_public_key) {
            if sender_balance >= transaction.amount {
                  let tx_id = transaction.id();
              
                 let new_utxo = UTXO {
                      tx_id, // Use signature as a transaction ID (you can use a better ID)
                    output_index: self.utxos.get(&transaction.receiver).unwrap_or(&vec![]).len(),
                    amount: transaction.amount,
                    receiver: transaction.receiver.clone(),
                 };
                  // Add UTXOs to the receiver
        self.utxos.entry(transaction.receiver.clone()).or_insert(vec![]).push(new_utxo);
          self.pending_transactions.push(transaction); // Add to pending transactions if valid
            } else {
                  println!("Transaction failed: insufficient UTXO"); // Notify insufficient UTXO
            }
        } else {
            println!("Transaction failed: invalid signature"); // Notify invalid signature
        }
    }

    // Method to mine pending transactions and create a new block
    fn mine_pending_transactions(&mut self, miner_address: String) {
        if self.pending_transactions.is_empty() {
            println!("No transactions to mine."); // Notify if no transactions are pending
            return; // Exit if no transactions to mine
        }

        // Get the hash of the latest block to link the new block
        let previous_hash = self.get_latest_block().hash.clone();
        
        // Create a new block with the pending transactions
        let new_block = Block::new(
            self.chain.len() as u64, // Block index
            previous_hash, // Previous block hash
            self.pending_transactions.clone(), // Clone the pending transactions
            self.difficulty, // Difficulty level
        );

        // Display the transactions included in this block
        println!("Block {} contains the following transactions:", new_block.index);
        for transaction in &new_block.transactions {
            println!("{:?}", transaction); // Print each transaction
        }

        // Add the new block to the chain
        self.chain.push(new_block);
         // Update balances for the transactions in the newly mined block in UTXO
         for transaction in &self.pending_transactions {
        // Deduct the transaction amount from the sender's balance
        if let Some(sender_utxos) = self.utxos.get_mut(&transaction.sender) {
            let total_amount: u64 = sender_utxos.iter().map(|utxo| utxo.amount).sum();
            if total_amount >= transaction.amount {
                // Process each UTXO and create new UTXOs
                let mut amount_to_spend = transaction.amount;

                // Create new UTXOs for the transaction
                for utxo in sender_utxos.clone() {
                    if amount_to_spend == 0 {
                        break; // If we have spent enough, stop
                    }
                    // Deduct from the UTXO if it's less than or equal to what we need
                    if utxo.amount <= amount_to_spend {
                        amount_to_spend -= utxo.amount; // Subtract the amount from the total to spend
                        // Remove this UTXO as it has been spent
                        sender_utxos.retain(|u| u.tx_id != utxo.tx_id); 
                    }
                }

                // Safely borrow the receiver's UTXOs after finishing the mutable borrow
                let output_index = self.utxos.get(&transaction.receiver).map_or(0, |v| v.len());
                
                // Add the transaction amount to the receiver's UTXOs
                self.utxos.entry(transaction.receiver.clone())
                    .or_insert(vec![]) // Initialize if not exists
                    .push(UTXO {
                        tx_id: transaction.id(), // Assuming you have an id() method in Transaction
                        output_index,
                        amount: transaction.amount,
                        receiver: transaction.receiver.clone(),
                    });

                // Handle miner's reward
                let miner_utxos = self.utxos.entry(miner_address.clone()).or_insert(vec![]); // Get or initialize miner's UTXOs
                
                // Reward the miner with mining reward, ensuring it doesn't exceed the total supply limit
                if self.total_mined + self.mining_reward <= TOTAL_SUPPLY {
                    miner_utxos.push(UTXO {
                        tx_id: format!("miner_reward_{}", self.chain.len()), // Example ID for mining reward
                        output_index: miner_utxos.len(), // Use miner's UTXOs length
                        amount: self.mining_reward,
                        receiver: miner_address.clone(),
                    });
                    self.total_mined += self.mining_reward; // Update total coins mined
                } else {
                    println!("Mining reward exceeds total supply limit."); // Notify if reward exceeds limit
                }
            } else {
                println!("Transaction failed: insufficient UTXO for sender"); // Notify insufficient UTXO
            }
        }
    }
        // Update balances for the transactions in the newly mined block for the normal one
        for transaction in &self.pending_transactions {
            // Deduct the transaction amount from the sender's balance
            if let Some(sender_balance) = self.balances.get_mut(&transaction.sender) {
                *sender_balance -= transaction.amount; // Update sender's balance
            }

            // Add the transaction amount to the receiver's balance
            self.balances.entry(transaction.receiver.clone()).or_insert(0); // Initialize if not exists
            *self.balances.get_mut(&transaction.receiver).unwrap() += transaction.amount; // Update receiver's balance
        }

        // Reward the miner with mining reward, ensuring it doesn't exceed the total supply limit
        if self.total_mined + self.mining_reward <= TOTAL_SUPPLY {
            self.balances.entry(miner_address.clone()).or_insert(0); // Initialize miner's balance if not exists
            *self.balances.get_mut(&miner_address).unwrap() += self.mining_reward; // Reward the miner
            self.total_mined += self.mining_reward; // Update total coins mined
        } else {
            println!("Mining reward exceeds total supply limit."); // Notify if reward exceeds limit
        }

        // Clear pending transactions after mining
        self.pending_transactions.clear();
    }

    // Method to display the entire blockchain with transactions
    fn display_chain(&self) {
        for block in &self.chain {
            println!("Block {} has the following transactions:", block.index);
            for transaction in &block.transactions {
                println!("{:?}", transaction); // Print each transaction in the block
            }
        }
    }
}

// Struct representing a wallet for managing RSA keys
#[derive(Debug)]
struct Wallet {
    private_key: RsaPrivateKey, // Private key for signing transactions
    public_key: RsaPublicKey, // Public key for receiving transactions
}

// Implementation of the Wallet struct
impl Wallet {
    // Constructor for creating a new wallet
    fn new() -> Self {
        let mut rng = OsRng; // Create a random number generator
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap(); // Generate a new RSA private key
        let public_key = private_key.to_public_key(); // Derive the public key from the private key
        Wallet { private_key, public_key } // Return a new Wallet instance
    }

    // Method to get the public key as a base64 encoded string
    fn get_public_key(&self) -> String {
        base64::encode(self.public_key.n().to_bytes_be()) // Encode and return the public key
    }
}

#[derive(Debug)]
struct Node {
    id: String,
    peers: Vec<String>, // List of peers
    blockchain: Blockchain,
}
// impl Node {
//     fn new(id: &str, difficulty: usize) -> Self {
//         Node {
//             id: id.to_string(),
//             peers: vec![],
//             blockchain: Blockchain::new(difficulty),
//         }
//     }

//     async fn send_block(&self, block: &Block) {
//         let block_json = serde_json::to_string(block).unwrap();
//         for peer in &self.peers {
//             match TcpStream::connect(peer).await {
//                 Ok(mut stream) => {
//                     let _ = stream.write_all(block_json.as_bytes()).await;
//                 }
//                 Err(e) => println!("Failed to connect to peer {}: {}", peer, e),
//             }
//         }
//     }

//     async fn listen_for_blocks(&mut self) {
//         let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
//         loop {
//             let (mut socket, _) = listener.accept().await.unwrap();
//             let mut buf = vec![0; 1024];
//             let n = socket.read(&mut buf).await.unwrap();
//             let block_json = String::from_utf8_lossy(&buf[..n]);
//             let block: Block = serde_json::from_str(&block_json).unwrap();
//             println!("Received block: {:?}", block);
//             self.blockchain.chain.push(block); // Add the received block to the blockchain
//         }
//     }
// }


// Main function where the program execution begins
#[tokio::main]
async fn main() {
    let difficulty = 4; // Difficulty level for mining
    let mining_reward = 50; // Reward for mining a new block
    //  let mut node = Node::new("node1", 4);
    // node.peers.push("127.0.0.1:8081".to_string()); // Add peers as needed

    // // Start listening for incoming blocks
    // tokio::spawn(async move {
    //     node.listen_for_blocks().await;
    // });
    

    // Create a new blockchain instance
    let mut blockchain = Blockchain::new(difficulty, mining_reward);

    // Create two wallets (users) for transactions
    let wallet1 = Wallet::new();
    let wallet2 = Wallet::new();

    // Set initial balance for wallet1
    blockchain.balances.insert(wallet1.get_public_key(), 100); // Initialize wallet1 with 100 coins

    // Create and process a transaction from wallet1 to wallet2
    let transaction = Transaction::new(&wallet1.private_key, wallet2.get_public_key(), 10);
    blockchain.create_transaction(transaction, &wallet1.public_key); // Create the transaction

    // Mine pending transactions and reward the miner (wallet1)
    blockchain.mine_pending_transactions(wallet1.get_public_key());

    // Check and display wallet balances after the transaction
    println!("Wallet1 balance: {}", blockchain.balances.get(&wallet1.get_public_key()).unwrap_or(&0));
    println!("Wallet2 balance: {}", blockchain.balances.get(&wallet2.get_public_key()).unwrap_or(&0));

    // Display the entire blockchain with all transactions
    blockchain.display_chain();
}
