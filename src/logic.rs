use std::{
    error::Error,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
};

use chrono::Local;
use log::info;

use crate::ctx::{Account, AddrToU64, Context, add_message};

pub fn on_total_size(ctx: Arc<Context>, addr: SocketAddr) -> Result<u64, Box<dyn Error>> {
    #[cfg(feature = "proxy-mode")]
    if let Some(url) = ctx.args.proxy_to.as_ref() {
        use bRAC::proto::{connect, read_messages};

        return read_messages(
            &mut connect(url, ctx.args.use_proxy.clone())?,
            1024, // TODO: softcode this
            0,
            false,
        )?
        .map(|o| o.1 as u64)
        .ok_or("err on reading in proxy mode".into()); // TODO: fix reading two times
    }

    Ok(ctx.get_total_messages(Some(addr.to_u64())))
}

pub fn on_total_data(
    ctx: Arc<Context>,
    addr: SocketAddr,
    _sent_size: Option<u64>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    #[cfg(feature = "proxy-mode")]
    if let Some(url) = ctx.args.proxy_to.as_ref() {
        use bRAC::proto::{connect, read_messages};

        return read_messages(
            &mut connect(url, ctx.args.use_proxy.clone())?,
            1024, // TODO: softcode this
            0,
            false,
        )?
        .map(|o| (o.0.join("\n") + "\n").as_bytes().to_vec())
        .ok_or("err on reading in proxy mode".into()); // TODO: fix reading two times
    }

    let mut messages = ctx.messages.read().unwrap().clone();
    let offset = ctx.messages_offset.load(Ordering::SeqCst);

    let mut messages = if offset > 0 {
        let mut buf = vec![0; offset as usize];
        buf.append(&mut messages);
        buf
    } else {
        messages
    };

    if let Some(splash) = &ctx.args.splash {
        messages.append(&mut splash.clone().as_bytes().to_vec());
    }

    let addr = addr.to_u64();

    let mut pos_offset = 0;

    for (x, pos, text) in ctx.notifications.read().unwrap().iter() {
        if *x == addr {
            // as usize: scary!
            let index = (pos + pos_offset) as usize;
            messages.splice(index..index, text.clone());
            pos_offset += pos;
        }
    }

    Ok(messages)
}

pub fn on_chunked_data(
    ctx: Arc<Context>,
    addr: SocketAddr,
    _sent_size: Option<u64>,
    client_has: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    #[cfg(feature = "proxy-mode")]
    if let Some(url) = ctx.args.proxy_to.as_ref() {
        use bRAC::proto::{connect, read_messages};

        return read_messages(
            &mut connect(url, ctx.args.use_proxy.clone())?,
            1024, // TODO: softcode this
            client_has as usize,
            true,
        )?
        .map(|o| (o.0.join("\n") + "\n").as_bytes().to_vec())
        .ok_or("err on reading in proxy mode".into());
    }

    let mut messages = ctx.messages.read().unwrap().clone();
    let offset = ctx.messages_offset.load(Ordering::SeqCst);

    let addr = addr.to_u64();

    let mut pos_offset = 0;

    for (x, pos, text) in ctx.notifications.read().unwrap().iter() {
        if *x == addr {
            let mut index = pos + pos_offset;

            if index < offset {
                continue;
            }
            index -= offset;

            if let Some(splash) = &ctx.args.splash {
                let splash_len = splash.len() as u64;

                if index < splash_len {
                    continue;
                }
                index -= splash_len
            }

            // as usize: scary!
            let index = index as usize;

            messages.splice(index..index, text.clone());
            pos_offset += pos;
        }
    }

    let client_has = if let Some(splash) = &ctx.args.splash {
        client_has - splash.len() as u64
    } else {
        client_has
    };

    if client_has <= offset {
        // that means client has only cleared messages
        // or he just has 0 messages
        // anyway, he needs all of the messages

        Ok(messages)
    } else {
        let client_has = (client_has - offset) as usize;

        // count size of messages without offset (cleared ones)
        // and send all the remaining messages for him

        Ok(messages[client_has..].to_vec())
    }
}

pub fn on_send_message(
    ctx: Arc<Context>,
    addr: SocketAddr,
    message: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "proxy-mode")]
    if let Some(url) = ctx.args.proxy_to.as_ref() {
        use bRAC::proto::{connect, send_message};

        return send_message(
            &mut connect(url, ctx.args.use_proxy.clone())?,
            &String::from_utf8_lossy(&message),
        ); // TODO: make brac accept message in bytes
    }

    if on_server_command(
        ctx.clone(),
        addr,
        None,
        String::from_utf8_lossy(&message).to_string(),
    )? {
        return Ok(());
    }

    if !ctx.args.auth_only {
        let mut message = message;
        message.truncate(ctx.args.message_limit);

        add_message(&message, ctx, Some(addr.ip()))?;
    }
    Ok(())
}

pub fn on_send_auth_message(
    ctx: Arc<Context>,
    addr: SocketAddr,
    name: &str,
    password: &str,
    text: &str,
) -> Result<Option<u8>, Box<dyn Error>> {
    #[cfg(feature = "proxy-mode")]
    if let Some(url) = ctx.args.proxy_to.as_ref() {
        use bRAC::proto::{connect, send_message_auth};

        return match send_message_auth(
            &mut connect(url, ctx.args.use_proxy.clone())?,
            name,
            password,
            text,
        ) {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(n)),
            Err(err) => Err(err),
        };
    }

    if let Some(acc) = ctx.get_account(name) {
        if acc.check_password(password) {
            if on_server_command(ctx.clone(), addr, Some(name.to_string()), text.to_string())? {
                return Ok(None);
            }

            let mut name = name.to_string();
            name.truncate(256); // TODO: softcode this

            let mut password = password.to_string();
            password.truncate(256); // TODO: softcode this

            let mut text = text.to_string();
            text.truncate(ctx.args.message_limit);

            add_message(format!("<{name}> {text}").as_bytes(), ctx, None)?;

            Ok(None)
        } else {
            Ok(Some(0x02))
        }
    } else {
        Ok(Some(0x01))
    }
}

pub fn on_register_user(
    ctx: Arc<Context>,
    addr: SocketAddr,
    name: &str,
    password: &str,
) -> Result<Option<u8>, Box<dyn Error>> {
    #[cfg(feature = "proxy-mode")]
    if let Some(url) = ctx.args.proxy_to.as_ref() {
        use bRAC::proto::{connect, register_user};

        return Ok(
            match register_user(
                &mut connect(url, ctx.args.use_proxy.clone())?,
                name,
                password,
            ) {
                Ok(true) => None,
                _ => Some(0x01),
            },
        );
    }

    let addr = addr.ip().to_string();

    let now: i64 = Local::now().timestamp_millis();

    if ctx.get_account(name).is_some()
        || (if let Some(acc) = ctx.get_account_by_addr(&addr) {
            ((now - acc.date()) as usize) < 1000 * ctx.args.register_timeout
        } else {
            false
        })
    {
        return Ok(Some(0x01));
    }

    let account = Account::new(name.to_string(), password.to_string(), addr, now);

    info!("user registered: {name}");

    ctx.push_account(account)?;

    Ok(None)
}

pub fn on_server_info(_: Arc<Context>, _: SocketAddr) -> Result<(u8, String), Box<dyn Error>> {
    Ok((0x03, format!("sRAC {}", env!("CARGO_PKG_VERSION"))))
}

/// return true on valid command (even unknown)
pub fn on_server_command(
    ctx: Arc<Context>,
    addr: SocketAddr,
    _auth: Option<String>,
    command: String,
) -> Result<bool, Box<dyn Error>> {
    if command.starts_with("?") {
        let mut split = command.split(" ");
        let command = match split.next() {
            Some(o) => &o[1..],
            None => return Ok(false),
        };
        let _args = split.collect::<Vec<&str>>();

        match command {
            "ping" => {
                ctx.push_notification(addr.to_u64(), "Pong!".as_bytes().to_vec());
            }
            _ => {}
        }
    }

    Ok(false)
}
