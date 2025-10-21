use std::{
    collections::HashMap,
    error::Error,
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Local, TimeZone};
use log::info;
use md5::{Digest, Md5};
use rand::{Rng, distr::Alphanumeric};

use crate::{
    Args,
    util::{format_message, grab_avatar, read_string, read_u32, sanitize_text},
};

pub trait AddrToU64 {
    fn to_u64(self) -> u64;
}

impl AddrToU64 for SocketAddr {
    fn to_u64(self) -> u64 {
        match self.ip() {
            IpAddr::V4(addr) => u32::from_be_bytes(addr.octets()) as u64,
            IpAddr::V6(addr) => u128::from_be_bytes(addr.octets()) as u64,
        }
    }
}

fn load_accounts(accounts_file: Option<String>) -> Vec<Account> {
    if let Some(accounts_file) = accounts_file.clone() {
        if fs::exists(&accounts_file).expect("error checking accounts file") {
            fs::read(&accounts_file)
                .expect("error reading accounts file")
                .split(|o| *o == b'\n')
                .filter(|o| !o.is_empty())
                .filter_map(|o| Account::from_bytes(o.to_vec()).ok())
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
    pub args: Arc<Args>,
    pub messages_file: Option<String>,
    pub accounts_file: Option<String>,
    pub messages: RwLock<Vec<u8>>,
    pub accounts: RwLock<Vec<Account>>,

    /// size of bytes that were removed from messages
    pub messages_offset: AtomicU64,

    /// vector of (ip, pos, text)
    ///
    /// ip is u32
    /// pos is usize: 0 ..= messages_offset + messages.len() + splash.len()
    /// text is byte vector
    ///  
    /// notification should disappear when its pos is less than messages_offset
    ///
    /// must be sorted by ascending pos
    pub notifications: RwLock<Vec<(u64, u64, Vec<u8>)>>,
    pub timeouts: RwLock<HashMap<u64, Duration>>,
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
            messages: RwLock::new(load_messages(messages_file)),
            accounts: RwLock::new(load_accounts(accounts_file)),
            messages_offset: AtomicU64::default(),
            notifications: RwLock::new(Vec::new()),
            timeouts: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_total_messages(&self, addr: Option<u64>) -> u64 {
        let mut total_messages = self.messages.read().unwrap().len() as u64;

        let offset = self.messages_offset.load(Ordering::SeqCst);
        total_messages += offset;

        if let Some(splash) = &self.args.splash {
            total_messages += splash.len() as u64
        }

        if let Some(addr) = addr {
            for (x, _, text) in self.notifications.read().unwrap().iter() {
                if *x == addr {
                    total_messages += text.len() as u64;
                }
            }
        }

        total_messages
    }

    pub fn push_notification(&self, addr: u64, msg: Vec<u8>) {
        self.notifications
            .write()
            .unwrap()
            .push((addr, self.get_total_messages(None), msg));
    }

    pub fn push_message(&self, msg: Vec<u8>) -> Result<(), Box<dyn Error>> {
        if let Some(messages_file) = self.messages_file.clone() {
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(messages_file)?;

            file.write_all(&msg)?;
            file.flush()?;
        }

        self.messages.write().unwrap().append(&mut msg.clone());

        let content = self.messages.read().unwrap().clone();

        if content.len() > self.args.messages_total_limit {
            let offset = content.len() - self.args.messages_total_limit;
            let content = content[offset..].to_vec();

            *self.messages.write().unwrap() = content.clone();
            self.messages_offset
                .fetch_add(offset as u64, Ordering::SeqCst);

            if let Some(messages_file) = self.messages_file.clone() {
                fs::write(messages_file, &content)?;
            }
        }

        Ok(())
    }

    pub fn get_account_by_addr(&self, addr: &str) -> Option<Account> {
        self.accounts
            .read()
            .unwrap()
            .iter()
            .find(|acc| acc.addr() == addr)
            .cloned()
    }

    pub fn get_account(&self, name: &str) -> Option<Account> {
        self.accounts
            .read()
            .unwrap()
            .iter()
            .find(|acc| acc.name() == name)
            .cloned()
    }

    pub fn push_account(&self, acc: Account) -> Result<(), Box<dyn Error>> {
        if let Some(accounts_file) = self.accounts_file.clone() {
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(accounts_file)?;

            file.write_all(&acc.to_bytes())?;
            file.write_all(b"\n")?;
            file.flush()?;
        }

        self.accounts.write().unwrap().push(acc);

        Ok(())
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

    pub fn from_bytes(text: Vec<u8>) -> Result<Self, Box<dyn Error>> {
        let mut cursor = Cursor::new(text);

        let name_len = read_u32(&mut cursor)? as usize;
        let salt_len = read_u32(&mut cursor)? as usize;
        let addr_len = read_u32(&mut cursor)? as usize;
        let pass_len = read_u32(&mut cursor)? as usize;
        let name = read_string(&mut cursor, name_len)?;
        let salt = read_string(&mut cursor, salt_len)?;
        let addr = read_string(&mut cursor, addr_len)?;

        let mut pass = vec![0; pass_len];
        cursor.read_exact(&mut pass)?;

        let mut date = [0; 8];
        cursor.read_exact(&mut date)?;
        let date = i64::from_le_bytes(date);

        Ok(Account {
            name,
            salt,
            pass,
            addr,
            date,
        })
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
    text: &[u8],
    ctx: Arc<Context>,
    addr: Option<IpAddr>,
) -> Result<(), Box<dyn Error>> {
    let prefix = message_prefix(Local::now().timestamp_millis(), addr.map(|o| o.to_string()));
    let mut msg = prefix.as_bytes().to_vec();

    if ctx.args.sanitize {
        let (text, avatar) = grab_avatar(&String::from_utf8_lossy(text));
        msg.append(&mut sanitize_text(&text).as_bytes().to_vec());
        if let Some(avatar) = avatar {
            msg.append(&mut format!("\x06!!AR!!{avatar}").as_bytes().to_vec());
        }
    } else {
        msg.append(&mut text.to_vec());
    }

    if let Some(msg) = format_message(addr.is_some(), String::from_utf8_lossy(&msg).to_string()) {
        info!("{}", msg);
    }

    msg.push(b'\n');
    ctx.push_message(msg)?;

    Ok(())
}
