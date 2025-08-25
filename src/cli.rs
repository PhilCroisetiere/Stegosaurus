use clap::Parser;
use secrecy::SecretString;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Stegosaurus - A simple steganography tool", long_about = None)]
pub struct Args {

    #[arg(long)]
    pub passphrase: SecretString,

    #[arg(long, default_value_t = 65536)] // Memory cost - controls memory usage of Argon2
    /// Memory cost parameter for Argon2 (in KiB). Higher values increase resistance 
    /// to hardware-accelerated attacks but require more memory. Default: 64 Mb.
    pub m_cost_kib: u32,

    #[arg(long, default_value_t = 3)]
    /// Time cost parameter for Argon2 (iterations). Higher values increase 
    /// computational difficulty and slow down brute force attempts. Default: 3.
    pub t_cost: u32,

    #[arg(long, default_value_t = 1)]
    /// Parallelism parameter for Argon2. Controls number of threads used.
    /// Higher values can improve performance on multi-core systems. Default: 1.
    pub p_cost: u32,

}