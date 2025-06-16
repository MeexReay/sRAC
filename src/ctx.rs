use std::{
    collections::HashMap,
    error::Error,
    fs::OpenOptions,
    io::{Cursor, Read, Write},
    net::IpAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bRAC::{chat::format_message, util::sanitize_text};
use chrono::{DateTime, Local, TimeZone};
use log::info;
use md5::{Digest, Md5};
use rand::{Rng, distr::Alphanumeric};

use crate::{Args, load_accounts, load_messages};

pub struct Context {
    pub args: Arc<Args>,
    pub messages_file: Option<String>,
    pub accounts_file: Option<String>,
    pub messages: RwLock<Vec<u8>>,
    pub accounts: RwLock<Vec<Account>>,
    pub messages_offset: AtomicU64,
    pub notifications: RwLock<HashMap<u32, Vec<u8>>>,
    pub timeouts: RwLock<HashMap<u32, Duration>>,
}

impl Context {
    pub fn new(
        args: Arc<Args>,
        messages_file: Option<String>,
        accounts_file: Option<String>,
    ) -> Self {
        Self {
            args,
            messages_file: messages_file.clone(),
            accounts_file: accounts_file.clone(),
            messages: RwLock::new(load_messages(messages_file.clone())),
            accounts: RwLock::new(load_accounts(accounts_file.clone())),
            timeouts: RwLock::new(HashMap::new()),
            messages_offset: AtomicU64::default(),
            notifications: RwLock::new(HashMap::new()),
        }
    }

    pub fn push_message(&self, msg: Vec<u8>) {
        if let Some(messages_file) = self.messages_file.clone() {
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(messages_file)
                .expect("error messages file open");

            file.write_all(&msg).expect("error messages file write");
            file.flush().expect("error messages file flush");
        }

        self.messages.write().unwrap().append(&mut msg.clone());

        let content = self.messages.read().unwrap().clone();

        if content.len() > self.args.messages_total_limit {
            let offset = content.len() - self.args.messages_total_limit;
            *self.messages.write().unwrap() = content[offset..].to_vec();
            self.messages_offset.store(offset as u64, Ordering::SeqCst);
        }
    }

    pub fn get_account_by_addr(&self, addr: &str) -> Option<Account> {
        for acc in self.accounts.read().unwrap().iter().rev() {
            if acc.addr() == addr {
                return Some(acc.clone());
            }
        }
        None
    }

    pub fn get_account(&self, name: &str) -> Option<Account> {
        for acc in self.accounts.read().unwrap().iter() {
            if acc.name() == name {
                return Some(acc.clone());
            }
        }
        None
    }

    pub fn push_account(&self, acc: Account) {
        if let Some(accounts_file) = self.accounts_file.clone() {
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(accounts_file)
                .expect("error accounts file open");

            file.write_all(&acc.to_bytes())
                .expect("error accounts file write");
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
    date: i64,
}

pub fn password_hash(name: &str, pass: &str, salt: &str) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(format!("{name}{pass}{salt}").as_bytes());
    hasher.finalize().to_vec()
}

pub fn password_salt() -> String {
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
            date,
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
            date,
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

pub fn add_message(
    buf: &mut Vec<u8>,
    context: Arc<Context>,
    addr: Option<IpAddr>,
    sanitize: bool,
) -> Result<(), Box<dyn Error>> {
    let mut msg = Vec::new();

    msg.append(
        &mut message_prefix(Local::now().timestamp_millis(), addr.map(|o| o.to_string()))
            .as_bytes()
            .to_vec(),
    );

    if sanitize {
        msg.append(
            &mut sanitize_text(&String::from_utf8_lossy(&buf.clone()))
                .as_bytes()
                .to_vec(),
        );
    } else {
        msg.append(buf);
    }

    if let Some(msg) = format_message(addr.is_some(), String::from_utf8_lossy(&msg).to_string()) {
        info!("{}", msg);
    }

    msg.push(b'\n');

    context.push_message(msg);

    Ok(())
}
