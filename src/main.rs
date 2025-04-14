use std::{env::args, error::Error, io::{Read, Write}, net::{TcpListener, TcpStream}, sync::{Arc, RwLock}, thread};

use chrono::{DateTime, Local, TimeZone};

fn message_prefix(time_millis: i64, address: &str) -> String {
    let datetime: DateTime<Local> = Local.timestamp_millis_opt(time_millis).unwrap();
    format!(
        "[{}] {{{}}}",
        datetime.format("%d.%m.%Y %H:%M"),
        address
    )
}

fn accept_stream(mut stream: TcpStream, messages: Arc<RwLock<Vec<u8>>>) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0];
    stream.read_exact(&mut buf)?;

    if buf[0] == 0x00 {
        let messages = messages.read().unwrap().clone();

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
    } else if buf[0] == 0x01 {
        let mut buf = vec![0; 4096];
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        let mut msg = Vec::new();

        msg.append(&mut message_prefix(
            Local::now().timestamp_millis(), 
            &stream.peer_addr()?.ip().to_string()).as_bytes().to_vec()
        );
        msg.push(b' ');
        msg.append(&mut buf);

        println!("{}", String::from_utf8_lossy(&msg));
        
        msg.push(b'\n');

        messages.write().unwrap().append(&mut msg.clone());

    } else if buf[0] == 0x02 {
        // sending authorized messages
    } else if buf[0] == 0x03 {
        // user registration
    }

    Ok(())
}

fn main() {
    let addr = args().skip(1).next().expect("needs at least 1 argument (host:port)");

    let listener = TcpListener::bind(&addr).expect("error trying bind to the provided addr");

    let messages = Arc::new(RwLock::new(Vec::new()));

    println!("Server started on {}", &addr);

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        let messages = messages.clone();

        thread::spawn(move || {
            let _ = accept_stream(stream, messages);
        });
    }
}
