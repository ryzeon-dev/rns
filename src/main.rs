#![allow(non_snake_case, unused_imports, unused_must_use, unused_variables)]

use std::net::{SocketAddr, TcpStream, Shutdown};
use std::time::Duration;
use std::io::{Read, Write};
use std::thread;
use std::sync::{Arc, Mutex};

const STD_PORTS: [u16; 13] = [
    20, 22, 80, 143, 443, 465, 1080, 1194, 3306, 5432, 7329, 9050, 51820
];

fn explainPorts() {
    println!("Standard ports explanation:");
    println!("    20     FTP data transfer");
    println!("    22     SSH");
    println!("    80     HTTP");
    println!("    143    IMAP");
    println!("    443    HTTPS");
    println!("    465    SMTP");
    println!("    1080   Socks proxy");
    println!("    1194   OpenVPN");
    println!("    3306   MySQL");
    println!("    5432   PostgreSQL");
    println!("    7329   Docker proxy");
    println!("    9050   TOR proxy");
    println!("    51820  Wireguard VPN");
    println!("!!! These ports are usually assigned to these functions, but they might have been reassigned");
}

fn makeu8Vec(ip: String) -> Vec<u8> {
    let splitted = ip.split(".");
    let mut uIP = Vec::<u8>::new();

    for octet in splitted {
        uIP.push(octet.parse::<u8>().unwrap())
    }

    return uIP;
}

fn makeBaseIP(ip: &Vec<u8>, mask: &Vec<u8>) -> Vec<u8> {
    let mut baseIP = Vec::<u8>::new();

    for i in 0..4 {
        baseIP.push(ip[i] & mask[i]);
    }

    return baseIP
}

fn makeEndIP(ip: &Vec<u8>, inverseMask: &Vec<u8>) -> Vec<u8> {
    let mut endIP = Vec::<u8>::new();

    for i in 0..4 {
        endIP.push(ip[i] | inverseMask[i]);
    }

    return endIP
}

fn makeInverseMask(mask: &Vec<u8>) -> Vec<u8> {
    let mut inverse = Vec::<u8>::new();

    for i in 0..4 {
        inverse.push(255 - mask[i]);
    }

    return inverse
}

fn increment(ip: &Vec<u8>) -> Vec<u8> {
    let mut next = ip.clone();
    
    for i in 0..4 {
        if next[3 - i] < 255 {
            next[3 - i] += 1;
            return next

        } else {
            next[3 - i] = 0;
        }
    }

    return next
}

fn ipToString(ip: &Vec<u8>) -> String {
    let mut res = Vec::<String>::new();

    for octet in ip {
        res.push(format!("{}", octet));
    }

    res.join(".").to_string()
}

fn check(ip: Vec<u8>, std: &bool, threads: Arc<Mutex<usize>>, report: Arc<Mutex<Vec<String>>>) {
    *threads.lock().unwrap() += 1;

    let formattedIP = {[ip[0], ip[1], ip[2], ip[3]]};
    let addr = &SocketAddr::from((formattedIP, 80));
    match TcpStream::connect_timeout(
        addr, 
        Duration::from_millis(1000)
    ) {
        Err(why) => {
            match why.kind() {
                std::io::ErrorKind::ConnectionRefused => {},
                _ => {
                    println!("[x] {} non responsive", ipToString(&ip));
                    *threads.lock().unwrap() -= 1;
                    return 
                }
            }
        },

        Ok(sock) => {}
    }
    println!("[*] {} found responsive", ipToString(&ip));

    let mut open = Vec::<u16>::new();

    if *std {
        for port in STD_PORTS {
            match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, port)), Duration::from_millis(100)) {
                Ok(sock) => {
                    open.push(port);
                    sock.shutdown(Shutdown::Both);
                },
                _ => {}
            }
        }
    } else {
        for port in 0..65535 {
            match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, port)), Duration::from_millis(100)) {
                Ok(sock) => {
                    open.push(port);
                    sock.shutdown(Shutdown::Both);
                },
                _ => {}
            }
        }
    }
    
    report.lock().unwrap().push(format!("[*] Found {}, open ports: {:?}", ipToString(&ip), open));
    *threads.lock().unwrap() -= 1;
}

fn main() {
    let mut args = std::env::args().collect::<Vec::<String>>();
   
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        println!("rns: Rust Network Scan");
        println!("usage: rns IPv4 NETMASK [OPTIONS]");
        println!("\noptions:");
        println!("    -std              Only check standard ports");
        println!("    -e | --explain    Explain standard ports");
        println!("    -h | --help       Show this message and exit");
        std::process::exit(0);
    }
    
    if args.contains(&"-e".to_string()) || args.contains(&"--explain".to_string()) {
        explainPorts();
        std::process::exit(0);
    }

    if args.len() < 3 {
        println!("Too few arguments");
        std::process::exit(1);
    }
    
    let mut stdPorts = false;

    match args.iter().position(|str| *str == "-std".to_string()) {
        None => {},
        Some(index) => {
            stdPorts = true;
            args.remove(index);
        }
    }

    let ip = makeu8Vec(args[1].clone());
    let mask = makeu8Vec(args[2].clone());
    let inverseMask = makeInverseMask(&mask);

    let baseIP = makeBaseIP(&ip, &mask);
    let endIP = makeEndIP(&ip, &inverseMask);

    println!("[*] Netmask: {}", ipToString(&mask));
    println!("[*] IP mask: {}", ipToString(&inverseMask));

    println!("[*] Base IP: {}", ipToString(&baseIP));
    println!("[*] End IP: {}\n", ipToString(&endIP));

    if stdPorts {
        println!("[*] Checking ports: {:?}\n", STD_PORTS);
    } else {
        println!("[*] Checking all ports (0-65535)\n");
    }
    

    let mut current = baseIP.clone();
    let threads = Arc::new(Mutex::new(0_usize));
    let report = Arc::new(Mutex::new(Vec::<String>::new()));

    while current != endIP {
        let ipClone = current.clone();

        let mutexClone = Arc::clone(&threads);
        let reportClone = Arc::clone(&report);

        thread::spawn(move ||{
            check(ipClone, &stdPorts, mutexClone, reportClone);
        });

        thread::sleep(Duration::from_millis(25));
        current = increment(&current);
    }

    while *threads.lock().unwrap() != 0_usize {
        thread::sleep(Duration::from_millis(100));
    }

    println!("\n[*] Final report:\n");

    for line in &*report.lock().unwrap() {
        println!("{}", line);
    }
}
