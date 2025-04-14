use std::{env::args, error::Error, io::{Read, Write}, net::{TcpListener, TcpStream}, sync::{Arc, RwLock}, thread};

fn accept_stream(mut stream: TcpStream, messages: Arc<RwLock<Vec<u8>>>) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0; 4096];
    let size = stream.read(&mut buf)?;
    buf.truncate(size);

    if buf[0] == 0x01 && size == 1 {
        stream.write_all(messages.read().unwrap().len().to_string().as_bytes())?;

        let mut buf = vec![0, 16];
        let size = stream.read(&mut buf)?;
        buf.truncate(size);

        if buf[0] == 0x01 {
            stream.write_all(&messages.read().unwrap())?;
        } else if buf[0] == 0x02 {
            let len: usize = String::from_utf8(buf[1..].to_vec())?.parse()?;
            stream.write_all(&messages.read().unwrap().clone()[len..])?;
        }
    } else if buf[0] == 0x01 {
        messages.write().unwrap().append(&mut buf[1..].to_vec());
    } else if buf[0] == 0x02 {
        
    } else if buf[0] == 0x03 {

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
