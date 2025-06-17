use std::{fs, sync::Arc};

use clap::Parser;
use log::info;

use crate::{
    ctx::{Account, Context},
    proto::run_listener,
};

pub mod ctx;
pub mod logic;
pub mod proto;

fn load_accounts(accounts_file: Option<String>) -> Vec<Account> {
    if let Some(accounts_file) = accounts_file.clone() {
        if fs::exists(&accounts_file).expect("error checking accounts file") {
            fs::read(&accounts_file)
                .expect("error reading accounts file")
                .split(|o| *o == b'\n')
                .filter(|o| !o.is_empty())
                .map(|o| Account::from_bytes(o.to_vec()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}

fn load_messages(messages_file: Option<String>) -> Vec<u8> {
    if let Some(messages_file) = messages_file.clone() {
        if fs::exists(&messages_file).expect("error checking messages file") {
            fs::read(&messages_file).expect("error reading messages file")
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}

#[derive(Parser, Debug)]
#[command(version)]
pub struct Args {
    /// Server host
    #[arg(short = 'H', long)]
    host: String,

    /// Sanitize messages
    #[arg(short, long)]
    sanitize: bool,

    /// Allow only authorized messages
    #[arg(short, long)]
    auth_only: bool,

    /// Splash message
    #[arg(short = 'S', long)]
    splash: Option<String>,

    /// Save messages to file
    #[arg(short = 'M', long)]
    messages_file: Option<String>,

    /// Save accounts to file
    #[arg(short = 'A', long)]
    accounts_file: Option<String>,

    /// Register timeout in seconds
    #[arg(short = 'r', long, default_value_t = 600)]
    register_timeout: usize,

    /// Message timeout in seconds
    #[arg(short = 'm', long, default_value_t = 5)]
    message_timeout: usize,

    /// Message limit in bytes
    #[arg(long, default_value_t = 4096)]
    message_limit: usize,

    /// Messages total limit in bytes
    #[arg(long, default_value_t = 4194304)]
    messages_total_limit: usize,

    /// Enable SSL (RACS)
    #[arg(short = 'l', long)]
    enable_ssl: bool,

    /// Set ssl certificate path (x509)
    #[arg(long)]
    ssl_key: Option<String>,

    /// Set ssl key path (x509)
    #[arg(long)]
    ssl_cert: Option<String>,

    /// Enable WRAC
    #[arg(short = 'w', long)]
    enable_wrac: bool,
}

fn main() {
    colog::init();

    let args = Arc::new(Args::parse());

    let context = Arc::new(Context::new(
        args.clone(),
        args.messages_file.clone(),
        args.accounts_file.clone(),
    ));

    info!("Server started on {}", &args.host);

    run_listener(context);
}
