use std::{
    error::Error,
    io::{Read, Write},
    net::SocketAddr,
    sync::Arc,
};

use crate::{ctx::Context, logic::*};

pub fn accept_rac_stream(
    mut stream: impl Read + Write,
    addr: SocketAddr,
    ctx: Arc<Context>,
) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0];
    stream.read_exact(&mut buf)?;

    if buf[0] == 0x00 {
        let total_size = on_total_size(ctx.clone(), addr.clone())?;
        stream.write_all(total_size.to_string().as_bytes())?;

        let mut id = vec![0];
        stream.read_exact(&mut id)?;

        if id[0] == 0x01 {
            stream.write_all(&on_total_data(ctx.clone(), addr.clone(), Some(total_size))?)?;
        } else if id[0] == 0x02 {
            let mut buf = vec![0; 10];
            let size = stream.read(&mut buf)?;
            buf.truncate(size);

            let client_has: u64 = String::from_utf8(buf)?.parse()?;
            stream.write_all(&on_chunked_data(
                ctx.clone(),
                addr.clone(),
                Some(total_size),
                client_has,
            )?)?;
        }
    } else if buf[0] == 0x01 {
        let mut buf = vec![0; ctx.args.message_limit];
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        on_send_message(ctx.clone(), addr.clone(), buf)?;
    } else if buf[0] == 0x02 {
        let mut buf = vec![0; ctx.args.message_limit + 2 + 512]; // FIXME: softcode this (512 = name + password)
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        let msg = String::from_utf8_lossy(&buf).to_string();

        let mut segments = msg.split("\n");

        let Some(name) = segments.next() else {
            return Ok(());
        };
        let Some(password) = segments.next() else {
            return Ok(());
        };
        let Some(text) = segments.next() else {
            return Ok(());
        };

        if let Some(resp_id) =
            on_send_auth_message(ctx.clone(), addr.clone(), name, password, text)?
        {
            stream.write_all(&[resp_id])?;
        }
    } else if buf[0] == 0x03 {
        let mut buf = vec![0; 1024];
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        let msg = String::from_utf8_lossy(&buf).to_string();

        let mut segments = msg.split("\n");

        let Some(name) = segments.next() else {
            return Ok(());
        };
        let Some(password) = segments.next() else {
            return Ok(());
        };

        if let Some(resp_id) = on_register_user(ctx.clone(), addr.clone(), name, password)? {
            stream.write_all(&[resp_id])?;
        }
    }

    Ok(())
}
