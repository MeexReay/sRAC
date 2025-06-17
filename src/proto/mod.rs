use std::{
    error::Error,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
};

use log::debug;
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

use crate::{
    ctx::Context,
    proto::{rac::accept_rac_stream, wrac::accept_wrac_stream},
};

pub mod rac;
pub mod wrac;

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

pub fn run_listener(ctx: Arc<Context>) {
    if ctx.args.enable_ssl {
        run_secure_listener(ctx);
    } else {
        run_normal_listener(ctx);
    }
}
