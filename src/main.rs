use std::io::{Read, Write};

fn main() {
    let mut c_listen = String::from("127.0.0.1:1082");
    {
        let mut ap = argparse::ArgumentParser::new();
        ap.set_description("socks5 Proxy");
        ap.refer(&mut c_listen)
            .add_option(&["-l", "--listen"], argparse::Store, "listen address");
        ap.parse_args_or_exit();
    }
    println!("Listen: {}", c_listen);

    let listener = std::net::TcpListener::bind(c_listen).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(data) => {
                std::thread::spawn(move || {
                    if let Err(err) = handler(&data) {
                        println!("Error: {:?}", err);
                    }
                });
            }
            Err(e) => {
                println!("Error: {:?}", e);
            }
        }
    }
}

fn handler(src_stream: &std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("src {}", src_stream.peer_addr().unwrap());

    // https://zh.wikipedia.org/wiki/SOCKS#SOCKS5

    let mut src_reader = src_stream.try_clone()?;
    let mut src_writer = src_stream.try_clone()?;

    let mut buf: Vec<u8> = vec![0x00; 256];

    // # Client -> Server
    // VER
    src_reader.read_exact(&mut buf[0..1])?;
    if buf[0] != 0x05 {
        panic!("VER must be 0x05");
    }
    // NMETHODS
    src_reader.read_exact(&mut buf[0..1])?;
    let n_auth = buf[0] as usize;
    // METHODS
    src_reader.read_exact(&mut buf[0..n_auth])?;

    // # Server -> Client
    src_writer.write(&[0x05])?;
    src_writer.write(&[0x00])?;

    // # Client -> Server
    // VER
    src_reader.read_exact(&mut buf[0..1])?;
    if buf[0] != 0x05 {
        panic!("VER must be 0x05");
    }
    // CMD
    src_reader.read_exact(&mut buf[0..1])?;
    if buf[0] != 0x01 {
        panic!("CMD only support 0x01");
    }
    // RSV
    src_reader.read_exact(&mut buf[0..1])?;
    if buf[0] != 0x00 {
        panic!("RSV must be 0x00");
    }
    // DST.ADDR
    src_reader.read_exact(&mut buf[0..1])?;
    let host = match buf[0] {
        0x01 => {
            src_reader.read_exact(&mut buf[0..4])?;
            std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]).to_string() // 1.2.3.4
        }
        0x03 => {
            src_reader.read_exact(&mut buf[0..1])?;
            let l = buf[0] as usize;
            src_reader.read_exact(&mut buf[0..l])?;
            String::from_utf8_lossy(&buf[0..l]).to_string() // abc.com
        }
        0x04 => {
            src_reader.read_exact(&mut buf[0..16])?;
            std::net::Ipv6Addr::new(
                (buf[0x00] as u16) << 8 | (buf[0x01] as u16),
                (buf[0x02] as u16) << 8 | (buf[0x03] as u16),
                (buf[0x04] as u16) << 8 | (buf[0x05] as u16),
                (buf[0x06] as u16) << 8 | (buf[0x07] as u16),
                (buf[0x08] as u16) << 8 | (buf[0x09] as u16),
                (buf[0x0a] as u16) << 8 | (buf[0x0b] as u16),
                (buf[0x0c] as u16) << 8 | (buf[0x0d] as u16),
                (buf[0x0e] as u16) << 8 | (buf[0x0f] as u16),
            )
            .to_string() // 1.2.3.4
        }
        _ => panic!("not support"),
    };
    // DST.PORT
    src_reader.read_exact(&mut buf[0..2])?;
    let port = ((buf[0] as u16) << 8) | (buf[1] as u16);
    let dst = format!("{}:{}", host, port);
    println!("dst {}", dst);

    let dst_stream = std::net::TcpStream::connect(&dst)?;
    let mut dst_reader = dst_stream.try_clone()?;
    let mut dst_writer = dst_stream.try_clone()?;

    // # Server -> Client  Response
    // VER
    src_writer.write(&[0x05])?;
    // STATUS
    src_writer.write(&[0x00])?;
    // RSV
    src_writer.write(&[0x00])?;
    // BND.ADDR
    src_writer.write(&[0x01])?;
    // IPV4
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;
    // BND.PORT  not used
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;

    // proxy
    std::thread::spawn(move || {
        std::io::copy(&mut src_reader, &mut dst_writer).ok();
    });
    std::io::copy(&mut dst_reader, &mut src_writer).ok();

    Ok(())
}
