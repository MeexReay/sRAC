use std::{collections::HashMap, error::Error, fs::{self, OpenOptions}, io::{Cursor, Read, Write}, net::{IpAddr, SocketAddr, TcpListener}, sync::{Arc, RwLock}, thread, time::Duration};

use bRAC::{chat::format_message, util::sanitize_text};
use chrono::{DateTime, Local, TimeZone};
use md5::{Digest, Md5};
use rand::{distr::Alphanumeric, Rng};

use clap::Parser;
use rustls::{pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer}, ServerConfig, ServerConnection, StreamOwned};
use tungstenite::{accept, Bytes, Message};


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

pub struct Context {
    messages_file: Option<String>,
    accounts_file: Option<String>,
    messages: RwLock<Vec<u8>>, 
    accounts: RwLock<Vec<Account>>,
    timeouts: RwLock<HashMap<u32, Duration>>,
    messages_offset: RwLock<usize>,
    notifications: RwLock<HashMap<u32, Vec<u8>>>
}

impl Context {
    fn new(
        messages_file: Option<String>,
        accounts_file: Option<String>
    ) -> Self {
        Self {
            messages_file: messages_file.clone(),
            accounts_file: accounts_file.clone(),
            messages: RwLock::new(load_messages(messages_file.clone())),
            accounts: RwLock::new(load_accounts(accounts_file.clone())),
            timeouts: RwLock::new(HashMap::new()),
            messages_offset: RwLock::new(0),
            notifications: RwLock::new(HashMap::new()),
        }
    }

    fn push_message(&self, msg: Vec<u8>) {
        if let Some(messages_file) = self.messages_file.clone() {
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(messages_file).expect("error messages file open");

            file.write_all(&msg).expect("error messages file write");
            file.flush().expect("error messages file flush");
        }

        self.messages.write().unwrap().append(&mut msg.clone());
    }

    fn get_account_by_addr(&self, addr: &str) -> Option<Account> {
        for acc in self.accounts.read().unwrap().iter().rev() {
            if acc.addr() == addr {
                return Some(acc.clone())
            }
        }
        None
    }

    fn get_account(&self, name: &str) -> Option<Account> {
        for acc in self.accounts.read().unwrap().iter() {
            if acc.name() == name {
                return Some(acc.clone())
            }
        }
        None
    }

    fn push_account(&self, acc: Account) {
        if let Some(accounts_file) = self.accounts_file.clone() {
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(accounts_file).expect("error accounts file open");

            file.write_all(&acc.to_bytes()).expect("error accounts file write");
            file.write_all(b"\n").expect("error accounts file write");
            file.flush().expect("error accounts file flush");
        }

        self.accounts.write().unwrap().push(acc);
    }
}

#[derive(Clone)]
pub struct Account {
    name: String,
    pass: Vec<u8>,
    salt: String,
    addr: String,
    date: i64
}

fn password_hash(name: &str, pass: &str, salt: &str) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(format!("{name}{pass}{salt}").as_bytes());
    hasher.finalize().to_vec()
}

fn password_salt() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

impl Account {
    pub fn new(name: String, password: String, addr: String, date: i64) -> Self {
        let salt = password_salt();

        Account {
            pass: password_hash(&name, &password, &salt),
            name: name.clone(),
            salt: salt.clone(),
            addr,
            date
        }
    }

    pub fn check_password(&self, password: &str) -> bool {
        password_hash(&self.name, password, &self.salt) == self.pass
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn date(&self) -> i64 {
        self.date
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.append(&mut (self.name.len() as u32).to_le_bytes().to_vec());
        data.append(&mut (self.salt.len() as u32).to_le_bytes().to_vec());
        data.append(&mut (self.addr.len() as u32).to_le_bytes().to_vec());
        data.append(&mut (self.pass.len() as u32).to_le_bytes().to_vec());
        data.append(&mut self.name.as_bytes().to_vec());
        data.append(&mut self.salt.as_bytes().to_vec());
        data.append(&mut self.addr.as_bytes().to_vec());
        data.append(&mut self.pass.clone());
        data.append(&mut self.date.to_le_bytes().to_vec());
        data
    }

    pub fn from_bytes(text: Vec<u8>) -> Self {
        let mut text = Cursor::new(text);

        let mut name_len = [0; 4];
        text.read_exact(&mut name_len).unwrap();
        let name_len = u32::from_le_bytes(name_len) as usize;

        let mut salt_len = [0; 4];
        text.read_exact(&mut salt_len).unwrap();
        let salt_len = u32::from_le_bytes(salt_len) as usize;

        let mut addr_len = [0; 4];
        text.read_exact(&mut addr_len).unwrap();
        let addr_len = u32::from_le_bytes(addr_len) as usize;

        let mut pass_len = [0; 4];
        text.read_exact(&mut pass_len).unwrap();
        let pass_len = u32::from_le_bytes(pass_len) as usize;

        let mut name = vec![0; name_len];
        text.read_exact(&mut name).unwrap();
        let name = String::from_utf8_lossy(&name).to_string();

        let mut salt = vec![0; salt_len];
        text.read_exact(&mut salt).unwrap();
        let salt = String::from_utf8_lossy(&salt).to_string();

        let mut addr = vec![0; addr_len];
        text.read_exact(&mut addr).unwrap();
        let addr = String::from_utf8_lossy(&addr).to_string();

        let mut pass = vec![0; pass_len];
        text.read_exact(&mut pass).unwrap();

        let mut date = [0; 8];
        text.read_exact(&mut date).unwrap();
        let date = i64::from_le_bytes(date);

        Account {
            name,
            salt,
            pass,
            addr,
            date
        }
    }
}

fn message_prefix(time_millis: i64, address: Option<String>) -> String {
    let datetime: DateTime<Local> = Local.timestamp_millis_opt(time_millis).unwrap();
    
    format!(
        "[{}]{} ",
        datetime.format("%d.%m.%Y %H:%M"),
        if let Some(addr) = address {
            format!(" {{{addr}}}")
        } else {
            String::new()
        }
    )
}

fn add_message(
    buf: &mut Vec<u8>, 
    context: Arc<Context>, 
    addr: Option<IpAddr>,
    sanitize: bool
) -> Result<(), Box<dyn Error>> {
    let mut msg = Vec::new();

    msg.append(&mut message_prefix(
        Local::now().timestamp_millis(), 
        addr.map(|o| o.to_string())
    ).as_bytes().to_vec());

    if sanitize {
        msg.append(&mut sanitize_text(&String::from_utf8_lossy(&buf.clone())).as_bytes().to_vec());
    } else {
        msg.append(buf);
    }

    if let Some(msg) = format_message(addr.is_some(), String::from_utf8_lossy(&msg).to_string()) {
        println!("{}", msg);
    }

    msg.push(b'\n');

    context.push_message(msg);

    Ok(())
}

fn accept_wrac_stream(
    stream: impl Read + Write, 
    addr: SocketAddr,
    context: Arc<Context>,
    args: Arc<Args>
) -> Result<(), Box<dyn Error>> {
    let mut websocket = match accept(stream) {
        Ok(i) => i,
        Err(e) => return Err(format!("accept websocket error: {}", e).into()),
    };

    while let Ok(msg) = websocket.read() {
        if let Some(data) = match msg {
            Message::Binary(o) => Some(o.to_vec()),
            Message::Text(o) => Some(o.as_bytes().to_vec()),
            Message::Close(_) => return Ok(()),
            _ => None
        } {
            let mut data = data;
            let Some(id) = data.drain(..1).next() else { return Ok(()) };

            if id == 0x00 {
                let mut messages = context.messages.read().unwrap().clone();

                if data.is_empty() {
                    if let Some(splash) = &args.splash {
                        websocket.write(Message::Binary(Bytes::from((messages.len() + splash.len()).to_string().as_bytes().to_vec())))?;
                    } else {
                        websocket.write(Message::Binary(Bytes::from(messages.len().to_string().as_bytes().to_vec())))?;
                    }
                    websocket.flush()?;
                } else {
                    let Some(id) = data.drain(..1).next() else { return Ok(()) };

                    if id == 0x01 {
                        if let Some(splash) = &args.splash {
                            messages.append(&mut splash.clone().as_bytes().to_vec());
                        }
                        websocket.write(Message::Binary(Bytes::from(messages)))?;
                        websocket.flush()?;
                    } else if id == 0x02 {
                        let last_size: usize = String::from_utf8(data)?.parse()?;
                        if let Some(splash) = &args.splash {
                            websocket.write(Message::Binary(Bytes::from(messages[(last_size - splash.len())..].to_vec())))?;
                        } else {
                            websocket.write(Message::Binary(Bytes::from(messages[last_size..].to_vec())))?;
                        }
                        websocket.flush()?;
                    }
                }
            } else if id == 0x01 {
                if !args.auth_only {
                    add_message(&mut data, context.clone(), Some(addr.ip()), args.sanitize)?;
                }
            } else if id == 0x02 {
                let msg = String::from_utf8_lossy(&data).to_string();
    
                let mut segments = msg.split("\n");
    
                let Some(name) = segments.next() else { return Ok(()) };
                let Some(password) = segments.next() else { return Ok(()) };
                let Some(text) = segments.next() else { return Ok(()) };
    
                if let Some(acc) = context.get_account(name) {
                    if acc.check_password(password) {
                        add_message(&mut text.as_bytes().to_vec(), context.clone(), None, args.sanitize)?;
                    } else {
                        websocket.write(Message::Binary(Bytes::from(vec![0x02])))?;
                        websocket.flush()?;
                    }
                } else {
                    websocket.write(Message::Binary(Bytes::from(vec![0x01])))?;
                    websocket.flush()?;
                }
            } else if id == 0x03 {
                let msg = String::from_utf8_lossy(&data).to_string();
    
                let mut segments = msg.split("\n");
    
                let Some(name) = segments.next() else { return Ok(()) };
                let Some(password) = segments.next() else { return Ok(()) };
    
                let addr = addr.ip().to_string();
    
                let now: i64 = Local::now().timestamp_millis();

                if context.get_account(name).is_some() || (
                    if let Some(acc) = context.get_account_by_addr(&addr) {
                        ((now - acc.date()) as usize) < 1000 * args.register_timeout
                    } else {
                        false
                    }
                ) {
                    websocket.write(Message::Binary(Bytes::from(vec![0x01])))?;
                    websocket.flush()?;
                    continue;
                }
    
                let account = Account::new(name.to_string(), password.to_string(), addr, now);

                println!("user registered: {name}");
    
                context.push_account(account);
            }
        }
    }


    Ok(())
}

fn accept_rac_stream(
    mut stream: impl Read + Write, 
    addr: SocketAddr,
    context: Arc<Context>,
    args: Arc<Args>
) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0];
    stream.read_exact(&mut buf)?;

    if buf[0] == 0x00 {
        let mut messages = context.messages.read().unwrap().clone();

        if let Some(splash) = &args.splash {
            stream.write_all((splash.len() + messages.len()).to_string().as_bytes())?;

            let mut id = vec![0];
            stream.read_exact(&mut id)?;
    
            if id[0] == 0x01 {
                messages.append(&mut splash.clone().as_bytes().to_vec());
                stream.write_all(&messages)?;
            } else if id[0] == 0x02 {
                let mut buf = vec![0; 10];
                let size = stream.read(&mut buf)?;
                buf.truncate(size);
    
                let len: usize = String::from_utf8(buf)?.parse()?;
                stream.write_all(&messages[(len - splash.len())..])?;
            }
        } else {
            stream.write_all(messages.len().to_string().as_bytes())?;

            let mut id = vec![0];
            stream.read_exact(&mut id)?;

            if id[0] == 0x01 {
                stream.write_all(&messages)?;
            } else if id[0] == 0x02 {
                let mut buf = vec![0; 10];
                let size = stream.read(&mut buf)?;
                buf.truncate(size);

                let len: usize = String::from_utf8(buf)?.parse()?;
                stream.write_all(&messages[len..])?;
            }
        }
    } else if buf[0] == 0x01 {
        if !args.auth_only {
            let mut buf = vec![0; 1024];
            let size = stream.read(&mut buf)?;
            buf.truncate(size);
    
            add_message(&mut buf, context.clone(), Some(addr.ip()), args.sanitize)?;
        }
    } else if buf[0] == 0x02 {
        let mut buf = vec![0; 8192];
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        let msg = String::from_utf8_lossy(&buf).to_string();

        let mut segments = msg.split("\n");

        let Some(name) = segments.next() else { return Ok(()) };
        let Some(password) = segments.next() else { return Ok(()) };
        let Some(text) = segments.next() else { return Ok(()) };

        if let Some(acc) = context.get_account(name) {
            if acc.check_password(password) {
                add_message(&mut text.as_bytes().to_vec(), context.clone(), None, args.sanitize)?;
            } else {
                stream.write_all(&[0x02])?;
            }
        } else {
            stream.write_all(&[0x01])?;
        }
    } else if buf[0] == 0x03 {
        let mut buf = vec![0; 1024];
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        let msg = String::from_utf8_lossy(&buf).to_string();

        let mut segments = msg.split("\n");

        let Some(name) = segments.next() else { return Ok(()) };
        let Some(password) = segments.next() else { return Ok(()) };

        let addr = addr.ip().to_string();

        let now: i64 = Local::now().timestamp_millis();

        if context.get_account(name).is_some() || (
            if let Some(acc) = context.get_account_by_addr(&addr) {
                ((now - acc.date()) as usize) < 1000 * args.register_timeout
            } else {
                false
            }
        ) {
            stream.write_all(&[0x01])?;
            return Ok(());
        }

        let account = Account::new(name.to_string(), password.to_string(), addr, now);

        println!("user registered: {name}");

        context.push_account(account);
    }

    Ok(())
}

fn accept_stream(
    stream: impl Read + Write, 
    addr: SocketAddr,
    context: Arc<Context>,
    args: Arc<Args>
) -> Result<(), Box<dyn Error>> {
    if args.enable_wrac {
        accept_wrac_stream(stream, addr, context, args)?;
    } else {
        accept_rac_stream(stream, addr, context, args)?;
    }

    Ok(())
}

fn run_normal_listener(
    context: Arc<Context>, 
    args: Arc<Args>
) {
    let listener = TcpListener::bind(&args.host).expect("error trying bind to the provided addr");

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        let context = context.clone();
        let args = args.clone();

        thread::spawn(move || {
            let Ok(addr) = stream.peer_addr() else { return; };
            match accept_stream(stream, addr, context, args) {
                Ok(_) => {},
                Err(e) => { println!("{}", e) },
            }
        });
    }
}

fn run_secure_listener(
    context: Arc<Context>, 
    args: Arc<Args>
) {
    let listener = TcpListener::bind(&args.host).expect("error trying bind to the provided addr");

    let server_config  = Arc::new(ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(CertificateDer::pem_file_iter(
            args.ssl_cert.clone().expect("--ssl-cert is required"))
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect(), 
            PrivateKeyDer::from_pem_file(
                args.ssl_key.clone().expect("--ssl-key is required")).unwrap()
            ).unwrap());

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        let context = context.clone();
        let args = args.clone();
        let server_config = server_config.clone();

        thread::spawn(move || {
            let Ok(addr) = stream.peer_addr() else { return; };

            let Ok(connection) = ServerConnection::new(server_config) else { return };
            let mut stream = StreamOwned::new(connection, stream);

            while stream.conn.is_handshaking() {
                let Ok(_) = stream.conn.complete_io(&mut stream.sock) else { return };
            }

            match accept_stream(stream, addr, context, args) {
                Ok(_) => {},
                Err(e) => { println!("{}", e) },
            }
        });
    }
}

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Server host
    #[arg(short='H', long)]
    host: String,

    /// Sanitize messages
    #[arg(short, long)]
    sanitize: bool,

    /// Allow only authorized messages
    #[arg(short, long)]
    auth_only: bool,

    /// Splash message
    #[arg(short='S', long)]
    splash: Option<String>,

    /// Save messages to file
    #[arg(short='M', long)]
    messages_file: Option<String>,

    /// Save accounts to file
    #[arg(short='A', long)]
    accounts_file: Option<String>,

    /// Register timeout in seconds
    #[arg(short='r', long, default_value_t = 600)]
    register_timeout: usize,

    /// Message timeout in seconds
    #[arg(short='m', long, default_value_t = 5)]
    message_timeout: usize,

    /// Message limit in bytes
    #[arg(long, default_value_t = 4096)]
    message_limit: usize,

    /// Messages total limit in bytes
    #[arg(long, default_value_t = 4194304)]
    messages_total_limit: usize,

    /// Enable SSL (RACS)
    #[arg(short='l', long)]
    enable_ssl: bool,

    /// Set ssl certificate path (x509)
    #[arg(long)]
    ssl_key: Option<String>,

    /// Set ssl key path (x509)
    #[arg(long)]
    ssl_cert: Option<String>,

    /// Enable WRAC
    #[arg(short='w', long)]
    enable_wrac: bool,
}


fn main() {
    let args = Arc::new(Args::parse());

    let context = Arc::new(Context::new(args.messages_file.clone(), args.accounts_file.clone()));

    println!("Server started on {}", &args.host);

    if args.enable_ssl {
        run_secure_listener(context, args);
    } else {
        run_normal_listener(context, args);
    }
}
