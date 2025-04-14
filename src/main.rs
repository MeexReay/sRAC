use std::{env::args, error::Error, io::Read, net::{TcpListener, TcpStream}, thread};

fn accept_stream(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0; 4096];

    stream.read(&mut buf)?;

    if buf[0]

    Ok(())
}

fn main() {
    let addr = args().skip(1).next().expect("needs at least 1 argument (host:port)");

    let listener = TcpListener::bind(&addr).expect("error trying bind to the provided addr");

    println!("Server started on {}", &addr);

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };

        thread::spawn(move || {
            let _ = accept_stream(stream);
        });
    }
}
