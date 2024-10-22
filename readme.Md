````markdown
# Cryptocurrency Blockchain Implementation

This project is a simple cryptocurrency blockchain implementation using Rust. It demonstrates key concepts of blockchain technology, cryptographic signing, and transaction management.

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Getting Started](#getting-started)
- [Code Structure](#code-structure)
  - [Transaction](#transaction)
  - [Block](#block)
  - [Blockchain](#blockchain)
  - [Wallet](#wallet)
- [How to Run the Code](#how-to-run-the-code)
- [License](#license)

## Features

- **Transaction Management**: Create and verify transactions between users.
- **Mining**: A proof-of-work mining mechanism to add blocks to the blockchain.
- **Wallet Management**: Generate wallets with RSA encryption for signing and verifying transactions.
- **Hashing**: Use SHA-256 for hashing blocks and transactions.

## Technologies Used

- **Rust**: The programming language used for this implementation.
- **Crates**:
  - `sha2`: For SHA-256 hashing.
  - `rand`: For random number generation.
  - `rsa`: For RSA encryption and decryption.

## Getting Started

To run this project, you'll need to have Rust installed on your machine. You can install Rust using [rustup](https://rustup.rs/).

### Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```
````

2. Build the project:

   ```bash
   cargo build
   ```

3. Run the project:
   ```bash
   cargo run
   ```

## Code Structure

### Transaction

```rust
#[derive(Debug, Clone)]
struct Transaction {
    sender: String,
    receiver: String,
    amount: u64,
    signature: Vec<u8>,
}
```

- **Description**: Represents a transaction between two parties.
- **Fields**:
  - `sender`: Base64 encoded public key of the sender.
  - `receiver`: Base64 encoded public key of the receiver.
  - `amount`: Amount being transferred.
  - `signature`: Digital signature of the transaction.

#### Methods:

- **new(sender: &RsaPrivateKey, receiver: String, amount: u64)**: Creates a new transaction and signs it with the sender's private key.
- **verify(&self, public_key: &RsaPublicKey) -> bool**: Verifies the signature of the transaction using the sender's public key.

### Block

```rust
#[derive(Debug)]
struct Block {
    index: u64,
    timestamp: u128,
    previous_hash: String,
    hash: String,
    nonce: u64,
    transactions: Vec<Transaction>,
}
```

- **Description**: Represents a block in the blockchain.
- **Fields**:
  - `index`: Position of the block in the chain.
  - `timestamp`: Time the block was created.
  - `previous_hash`: Hash of the previous block.
  - `hash`: Current block's hash.
  - `nonce`: Number used for mining (proof of work).
  - `transactions`: Transactions included in the block.

#### Methods:

- **new(index: u64, previous_hash: String, transactions: Vec<Transaction>, difficulty: usize) -> Block**: Creates a new block and calculates its hash.
- **calculate_hash(&self) -> String**: Calculates the hash of the block.
- **mine_block(&mut self, difficulty: usize)**: Mines the block to find a valid hash based on difficulty.

### Blockchain

```rust
#[derive(Debug)]
struct Blockchain {
    chain: Vec<Block>,
    difficulty: usize,
    pending_transactions: Vec<Transaction>,
    mining_reward: u64,
    balances: HashMap<String, u64>,
    total_mined: u64,
}
```

- **Description**: Represents the entire blockchain.
- **Fields**:
  - `chain`: List of blocks in the blockchain.
  - `difficulty`: Difficulty of mining.
  - `pending_transactions`: Transactions waiting to be added to a block.
  - `mining_reward`: Reward given to miners.
  - `balances`: Track wallet balances.
  - `total_mined`: Total coins mined.

#### Methods:

- **new(difficulty: usize, mining_reward: u64) -> Self**: Creates a new blockchain and initializes it with a genesis block.
- **create_genesis_block(&mut self)**: Creates the first block (genesis block).
- **create_transaction(&mut self, transaction: Transaction, sender_public_key: &RsaPublicKey)**: Creates and adds a transaction to the pending transactions.
- **mine_pending_transactions(&mut self, miner_address: String)**: Mines pending transactions and creates a new block.

### Wallet

```rust
#[derive(Debug)]
struct Wallet {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}
```

- **Description**: Represents a wallet for managing RSA keys.
- **Fields**:
  - `private_key`: Private key for signing transactions.
  - `public_key`: Public key for receiving transactions.

#### Methods:

- **new() -> Self**: Creates a new wallet with generated RSA keys.
- **get_public_key(&self) -> String**: Returns the public key as a base64 encoded string.

## How to Run the Code

1. After cloning the repository, navigate to the project directory.
2. Use `cargo run` to execute the program.
3. The console will display transaction details and wallet balances after mining.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
