use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
};

use log::{debug, info};

use clap::Parser;
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

use crate::{
    ctx::{Account, Context},
    rac::accept_rac_stream,
    wrac::accept_wrac_stream,
};

mod ctx;
mod logic;
mod rac;
mod wrac;

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

fn accept_stream(
    stream: impl Read + Write,
    addr: SocketAddr,
    ctx: Arc<Context>,
) -> Result<(), Box<dyn Error>> {
    if ctx.args.enable_wrac {
        accept_wrac_stream(stream, addr, ctx)?;
    } else {
        accept_rac_stream(stream, addr, ctx)?;
    }

    Ok(())
}

fn run_normal_listener(ctx: Arc<Context>) {
    let listener =
        TcpListener::bind(&ctx.args.host).expect("error trying bind to the provided addr");

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        let ctx = ctx.clone();

        thread::spawn(move || {
            let Ok(addr) = stream.peer_addr() else {
                return;
            };
            match accept_stream(stream, addr, ctx) {
                Ok(_) => {}
                Err(e) => {
                    debug!("{}", e)
                }
            }
        });
    }
}

fn run_secure_listener(ctx: Arc<Context>) {
    let listener =
        TcpListener::bind(&ctx.args.host).expect("error trying bind to the provided addr");

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                CertificateDer::pem_file_iter(
                    ctx.args.ssl_cert.clone().expect("--ssl-cert is required"),
                )
                .unwrap()
                .map(|cert| cert.unwrap())
                .collect(),
                PrivateKeyDer::from_pem_file(
                    ctx.args.ssl_key.clone().expect("--ssl-key is required"),
                )
                .unwrap(),
            )
            .unwrap(),
    );

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        let ctx = ctx.clone();
        let server_config = server_config.clone();

        thread::spawn(move || {
            let Ok(addr) = stream.peer_addr() else {
                return;
            };

            let Ok(connection) = ServerConnection::new(server_config) else {
                return;
            };
            let mut stream = StreamOwned::new(connection, stream);

            while stream.conn.is_handshaking() {
                let Ok(_) = stream.conn.complete_io(&mut stream.sock) else {
                    return;
                };
            }

            match accept_stream(stream, addr, ctx) {
                Ok(_) => {}
                Err(e) => {
                    debug!("{}", e)
                }
            }
        });
    }
}

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
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

    if args.enable_ssl {
        run_secure_listener(context);
    } else {
        run_normal_listener(context);
    }
}
