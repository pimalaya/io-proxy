//! Tunnel a TCP connection through a SOCKS5 proxy, then print whatever
//! the target sends back.
//!
//! Bring a SOCKS5 proxy up first (for example the one spawned by
//! tests/proxy.sh on 127.0.0.1:1080), then:
//!
//! ```sh
//! cargo run --example std_socks5 -- 127.0.0.1:1080 example.com 80
//! ```

use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
};

use io_proxy::{client::connect_socks5, socks::v5::address::Socks5Address};

fn main() {
    env_logger::init();

    let mut args = env::args().skip(1);
    let proxy = args.next().unwrap_or_else(|| "127.0.0.1:1080".into());
    let host = args.next().unwrap_or_else(|| "example.com".into());
    let port: u16 = args
        .next()
        .unwrap_or_else(|| "80".into())
        .parse()
        .expect("target port");

    let mut stream = TcpStream::connect(&proxy).expect("connect to proxy");
    let target = Socks5Address::new(&host, port).expect("build target address");
    connect_socks5(&mut stream, target, None).expect("socks5 handshake");

    // the tunnel is now live and positioned at the target's first byte;
    // send a trivial request and print the first chunk of the reply.
    let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write request");

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).expect("read response");
    print!("{}", String::from_utf8_lossy(&buf[..n]));
}
