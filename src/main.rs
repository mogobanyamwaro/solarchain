extern crate sha2;
extern crate rand;


use rand::rngs::OsRng;
use sha2::{Sha256,Digest};
use rsa::{PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};


use std::time::{SystemTime,UNIX_EPOCH};




#[derive(Debug)]
struct Transaction {
    sender:String,
    receiver:String,
    amount:u64,
    signature:Vec<u8>
}


impl Transaction{
    // Function to create a new transaction and sign it

    fn new(sender:&RsaPrivateKey,receiver:String,amount:u64)->Self{
        let sender_public_key = sender.to_public_key();
        let sender_key_str = base64::encode(sender_public_key.n().to_bytes_be());
        let transaction_data = format!("{}{}{}",sender_key_str,receiver,amount);

          // Hash the transaction data
        let hashed_data = Sha256::digest(transaction_data.as_bytes());
          // Specify the hash type as Sha256 for the padding scheme
 let padding = PaddingScheme::new_pkcs1v15_sign(None);
     let signature = sender
            .sign(padding, &hashed_data)
            .unwrap();
       Transaction {
            sender: sender_key_str, 
            receiver,
            amount,
            signature,
        }
    }

      // Function to verify the transaction's signature
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
struct Block{
    index:u64,
    timestamp:u128 ,
    previous_hash:String,
    hash:String,
    nounce:u64,
    transactions: Vec<Transaction>,
}


impl Block {
    fn new(index:u64,previous_hash:String,transactions: Vec<Transaction>,difficulty:usize)->Block{
        let timestamp= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let hash = String::new();
        let nounce = 0;
        let mut block = Block { index, timestamp, previous_hash, hash, nounce,transactions };
        block.hash = block.calculate_hash();
        block.mine_block(difficulty);
        block
    }
  // Function to calculate the hash of the block
    fn calculate_hash(&self)->String{
        let input = format!("{}{}{}{}",self.index,self.timestamp,self.previous_hash,self.nounce);
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}",hasher.finalize())
    }
    // Function to mine the block (i.e., find a hash that meets the difficulty requirement)
    fn mine_block(&mut self,difficulty:usize){
        let target = "0".repeat(difficulty); // The target has must have `difficulty` number of leading zeros

        while &self.hash[..difficulty]!=target{
            self.nounce +=1;
            self.hash = self.calculate_hash();
        }
        println!("Block mined! Hash: {}",self.hash)
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

fn main(){
    let difficulty = 4;

     // Create two wallets
    let wallet1 = Wallet::new();
    let wallet2 = Wallet::new();
    // Create a transaction from wallet1 to wallet2
    let transaction = Transaction::new(&wallet1.private_key, wallet2.get_public_key(), 50);
       // Verify the transaction using wallet1's public key
    assert!(transaction.verify(&wallet1.public_key), "Transaction verification failed!");

  // Create a genesis block with this transaction
    let genesis_block = Block::new(0, String::from("0"), vec![transaction], difficulty);
    println!("{:?}", genesis_block);

      // Create a new block linked to the genesis block with another transaction
    let transaction2 = Transaction::new(&wallet2.private_key, wallet1.get_public_key(), 20);
    let new_block = Block::new(1, genesis_block.hash, vec![transaction2], difficulty);
    println!("{:?}", new_block);

}