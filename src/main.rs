use std::sync::Arc;

use clap::Parser;
use log::info;

use crate::{ctx::Context, proto::run_listener, util::parse_rac_url};

pub mod ctx;
pub mod logic;
pub mod proto;
pub mod util;

#[derive(Parser, Debug)]
#[command(version)]
pub struct Args {
    /// Server host (RAC URL)
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

    /// Set ssl certificate path (x509)
    #[arg(long)]
    ssl_key: Option<String>,

    /// Set ssl key path (x509)
    #[arg(long)]
    ssl_cert: Option<String>,

    /// Enable Proxy-Mode (RAC URL)
    #[cfg(feature = "proxy-mode")]
    #[arg(short = 'P', long)]
    proxy_to: Option<String>,

    /// Use Socks5 proxy (to connect to the server in proxy-mode)
    #[cfg(feature = "proxy-mode")]
    #[arg(long)]
    use_proxy: Option<String>,
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

    let (host, ssl, wrac) = parse_rac_url(&args.host).expect("INVALID RAC URL");

    run_listener(context, &host, ssl, wrac);
}
