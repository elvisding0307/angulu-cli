use angulu::crypter::chacha20::ChaCha20CipherAlgorithm;
use angulu::crypter::sm4::Sm4CipherAlgorithm;
use angulu::crypter::{StringCrypter, StringCrypterTrait};
use clap::{Parser, ValueEnum};
use rpassword::prompt_password;
use std::io::{self, BufRead};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum CipherMode {
    #[value(name = "chacha20")]
    ChaCha20,
    #[value(name = "sm4")]
    Sm4,
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
struct Action {
    /// Encrypt the input
    #[arg(short, long)]
    encrypt: bool,

    /// Decrypt the input
    #[arg(short, long)]
    decrypt: bool,
}

/// A simple command-line tool for encryption and decryption.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    action: Action,

    /// Cipher mode to use
    #[arg(short, long, value_enum, default_value_t = CipherMode::ChaCha20)]
    mode: CipherMode,
}

fn main() {
    let args = Args::parse();

    // 检查是否同时加密解密
    if args.action.decrypt && args.action.encrypt {
        eprintln!("Error: cannot encrypt and decrypt at the same time!");
        std::process::exit(-1);
    } else if !args.action.decrypt && !args.action.encrypt {
        eprintln!("Error: must choose either encrypt or decrypt!");
        std::process::exit(-1);
    }

    let password = prompt_password("Enter password: ").expect("Cannot read password!");

    let crypter: Box<dyn StringCrypterTrait> = match args.mode {
        CipherMode::ChaCha20 => Box::new(StringCrypter::<ChaCha20CipherAlgorithm>::default()),
        CipherMode::Sm4 => Box::new(StringCrypter::<Sm4CipherAlgorithm>::default()),
    };

    let stdin = io::stdin();
    for (index, line) in stdin.lock().lines().enumerate() {
        let line = line.expect("Cannot read line from stdin.");
        let line = line.trim();
        // 跳过空行
        if line.is_empty() {
            continue;
        }

        let result = if args.action.encrypt {
            crypter.encrypt(line, &password)
        } else {
            crypter.decrypt(line, &password)
        };

        match result {
            Ok(processed_line) => println!("{}", processed_line),
            Err(e) => eprintln!("Line {}: Error: {}", index, e),
        }
    }
}
