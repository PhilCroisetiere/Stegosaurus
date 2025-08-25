mod cli;
mod passphrase;

use crate::cli::Args;
use crate::passphrase::{Argon2Params, passphrase_to_root_and_salt, key_generation};
use clap::Parser;
use secrecy::SecretString;

fn main() {
    let args = Args::parse();


    let _passphrase: SecretString = args.passphrase;


    let argon2_params = Argon2Params {
        m_cost_kib: args.m_cost_kib,   
        t_cost: args.t_cost,           
        p_cost: args.p_cost,           
    };

    let primitives = passphrase_to_root_and_salt(&_passphrase, argon2_params).expect("Crash on passphrase processing");

    let keys = key_generation(&primitives.root).expect("Crash on key generation");

    println!("Derived Keys:");
    println!("Encryption Key: {:x?}", keys.enc_key);
    println!("PRNG Key:       {:x?}", keys.prng_key);
    println!("Salt:           {:x?}", primitives.salt);

    drop(_passphrase); 
    drop(primitives);
    drop(keys);


}
