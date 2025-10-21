use std::{
    error::Error,
    io::{Read, Write},
    net::SocketAddr,
    sync::Arc,
};

use tungstenite::{accept, Bytes, Message};

use crate::{ctx::Context, logic::*};

pub fn accept_wrac_stream(
    stream: impl Read + Write,
    addr: SocketAddr,
    ctx: Arc<Context>,
) -> Result<(), Box<dyn Error>> {
    let mut websocket = match accept(stream) {
        Ok(i) => i,
        Err(e) => return Err(format!("accept websocket error: {}", e).into()),
    };

    let mut sent_size = None;

    while let Ok(msg) = websocket.read() {
        if let Some(data) = match msg {
            Message::Binary(o) => Some(o.to_vec()),
            Message::Text(o) => Some(o.as_bytes().to_vec()),
            Message::Close(_) => return Ok(()),
            _ => None,
        } {
            let mut data = data;
            let Some(id) = data.drain(..1).next() else {
                return Ok(());
            };

            if id == 0x00 {
                if data.is_empty() {
                    let total_size = on_total_size(ctx.clone(), addr)?;
                    sent_size = Some(total_size);

                    websocket.write(Message::Binary(Bytes::from(
                        total_size.to_string().as_bytes().to_vec(),
                    )))?;
                    websocket.flush()?;
                } else {
                    let Some(id) = data.drain(..1).next() else {
                        return Ok(());
                    };

                    if id == 0x01 {
                        websocket.write(Message::Binary(Bytes::from(on_total_data(
                            ctx.clone(),
                            addr,
                            sent_size,
                        )?)))?;
                        websocket.flush()?;
                    } else if id == 0x02 {
                        let client_has = String::from_utf8(data)?.parse()?;
                        websocket.write(Message::Binary(Bytes::from(on_chunked_data(
                            ctx.clone(),
                            addr,
                            sent_size,
                            client_has,
                        )?)))?;
                        websocket.flush()?;
                    }
                }
            } else if id == 0x01 {
                on_send_message(ctx.clone(), addr, data)?;
            } else if id == 0x02 {
                let msg = String::from_utf8_lossy(&data).to_string();

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
                    on_send_auth_message(ctx.clone(), addr, name, password, text)?
                {
                    websocket.write(Message::Binary(Bytes::from(vec![resp_id])))?;
                    websocket.flush()?;
                }
            } else if id == 0x03 {
                let msg = String::from_utf8_lossy(&data).to_string();

                let mut segments = msg.split("\n");

                let Some(name) = segments.next() else {
                    return Ok(());
                };

                let Some(password) = segments.next() else {
                    return Ok(());
                };

                if let Some(resp_id) = on_register_user(ctx.clone(), addr, name, password)? {
                    websocket.write(Message::Binary(Bytes::from(vec![resp_id])))?;
                    websocket.flush()?;
                }
            } else if id == 0x69 {
                let (protocol_version, name) = on_server_info(ctx.clone(), addr)?;

                let mut data = Vec::new();
                data.push(protocol_version);
                data.append(&mut name.as_bytes().to_vec());

                websocket.write(Message::Binary(Bytes::from(data)))?;
                websocket.flush()?;
            }
        }
    }

    Ok(())
}
