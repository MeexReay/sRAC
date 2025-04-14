use std::{error::Error, io::{Read, Write}, net::{IpAddr, TcpListener, TcpStream}, sync::{Arc, RwLock}, thread};

use bRAC::{chat::format_message, util::sanitize_text};
use chrono::{DateTime, Local, TimeZone};
use md5::{Digest, Md5};
use rand::{distr::Alphanumeric, Rng};

use clap::Parser;


#[derive(Clone)]
pub struct Account {
    name: String,
    pass: String,
    salt: String
}

fn password_hash(name: &str, pass: &str, salt: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(format!("{name}{pass}{salt}").as_bytes());
    let result = hasher.finalize().to_vec();
    String::from_utf8_lossy(&result).to_string()
}

fn password_salt() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

impl Account {
    pub fn new(name: String, password: String) -> Self {
        let salt = password_salt();

        Account {
            pass: password_hash(&name, &password, &salt),
            name: name.clone(),
            salt: salt.clone()
        }
    }

    pub fn check_password(&self, password: &str) -> bool {
        password_hash(&self.name, password, &self.salt) == self.pass
    }

    pub fn name(&self) -> &str {
        &self.name
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
    messages: Arc<RwLock<Vec<u8>>>, 
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

    messages.write().unwrap().append(&mut msg.clone());

    Ok(())
}

fn accept_stream(
    args: Arc<Args>,
    mut stream: TcpStream, 
    messages: Arc<RwLock<Vec<u8>>>,
    accounts: Arc<RwLock<Vec<Account>>>
) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0];
    stream.read_exact(&mut buf)?;

    if buf[0] == 0x00 {
        let mut messages = messages.read().unwrap().clone();

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
    
            add_message(&mut buf, messages.clone(), Some(stream.peer_addr()?.ip()), args.sanitize)?;
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

        for user in accounts.read().unwrap().iter() {
            if user.name() == name {
                if user.check_password(password) {
                    add_message(&mut text.as_bytes().to_vec(), messages.clone(), None, args.sanitize)?;
                } else {
                    stream.write_all(&[0x02])?;
                }
                return Ok(());
            }
        }

        stream.write_all(&[0x01])?;
    } else if buf[0] == 0x03 {
        let mut buf = vec![0; 1024];
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        let msg = String::from_utf8_lossy(&buf).to_string();

        let mut segments = msg.split("\n");

        let Some(name) = segments.next() else { return Ok(()) };
        let Some(password) = segments.next() else { return Ok(()) };

        for user in accounts.read().unwrap().iter() {
            if user.name() == name {
                stream.write_all(&[0x01])?;
                return Ok(());
            }
        }
        
        accounts.write().unwrap().push(Account::new(name.to_string(), password.to_string()));
    }

    Ok(())
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
    splash: Option<String>
}

fn main() {
    let args = Arc::new(Args::parse());

    let listener = TcpListener::bind(&args.host).expect("error trying bind to the provided addr");

    let messages = Arc::new(RwLock::new(Vec::new()));
    let accounts = Arc::new(RwLock::new(Vec::new()));

    println!("Server started on {}", &args.host);

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        let messages = messages.clone();
        let accounts = accounts.clone();
        let args = args.clone();

        thread::spawn(move || {
            let _ = accept_stream(args, stream, messages, accounts);
        });
    }
}
