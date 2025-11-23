use std::io::{self, BufRead};

use angulu::crypter::chacha20::ChaCha20CipherAlgorithm;
use angulu::crypter::sm4::Sm4CipherAlgorithm;
use angulu::crypter::{StringCrypter, StringCrypterTrait};

use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;

/// cipher algorithm for cli arguments
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum CliCipherAlgorithm {
    #[value(name = "chacha20")]
    ChaCha20,
    #[value(name = "sm4")]
    Sm4,
}

/// crypter args for cli arguments
#[derive(Debug, clap::Args)]
struct CliCrypterArgs {
    /// cipher algorithm to use
    #[arg(short='a', long, value_enum, default_value_t = CliCipherAlgorithm::ChaCha20)]
    cipher_algorithm: CliCipherAlgorithm,
}

impl CliCrypterArgs {
    #[inline]
    fn to_string_crypter(&self) -> Box<dyn StringCrypterTrait> {
        match self.cipher_algorithm {
            CliCipherAlgorithm::ChaCha20 => {
                Box::new(StringCrypter::<ChaCha20CipherAlgorithm>::default())
            }
            CliCipherAlgorithm::Sm4 => Box::new(StringCrypter::<Sm4CipherAlgorithm>::default()),
        }
    }
}

/// command for cli arguments
#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Encrypt the input
    Encrypt(CliCrypterArgs),
    /// Decrypt the input
    Decrypt(CliCrypterArgs),
}

/// A simple command-line tool for encryption and decryption.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[command(subcommand)]
    command: CliCommand,
}

/// mode for crypter
enum CrypterMode {
    Encrypt,
    Decrypt,
}

struct Crypter {
    crypter_mode: CrypterMode,
    string_crypter: Box<dyn StringCrypterTrait>,
}

impl Crypter {
    pub fn new(cmd: CliCommand) -> Self {
        match cmd {
            CliCommand::Encrypt(args) => Crypter {
                crypter_mode: CrypterMode::Encrypt,
                string_crypter: args.to_string_crypter(),
            },
            CliCommand::Decrypt(args) => Crypter {
                crypter_mode: CrypterMode::Decrypt,
                string_crypter: args.to_string_crypter(),
            },
        }
    }
    pub fn crypt(&self, input: &str, password: &str) -> angulu::Result<String> {
        match self.crypter_mode {
            CrypterMode::Encrypt => self.string_crypter.encrypt(input, password),
            CrypterMode::Decrypt => self.string_crypter.decrypt(input, password),
        }
    }
}

fn main() {
    let args = CliArgs::parse();

    let password = prompt_password("Enter password: ").expect("Cannot read password!");

    let crypter = Crypter::new(args.command);

    for (index, line) in io::stdin().lock().lines().enumerate() {
        let line = line.expect("Cannot read line");
        let line = line.trim_matches(|ch| ch == '\r' || ch == '\n');
        if line.is_empty() {
            continue;
        }

        let result = crypter.crypt(line, &password);
        match result {
            Ok(processed_line) => println!("{}", processed_line),
            Err(e) => eprintln!("Line {}: Error: {}", index, e),
        }
    }
}
