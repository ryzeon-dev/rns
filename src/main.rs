#![allow(non_snake_case, unused_must_use, dead_code)]

mod threadpool;

use std::net::{SocketAddr, TcpStream, Shutdown};
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use regex;

const STD_PORTS: [u16; 17] = [
    20, 21, 22, 53, 80, 143, 443, 445, 465, 1080, 1194, 3306, 5432, 7329, 9050, 9100, 51820
];

fn explainPorts() {
    println!("Standard ports explanation:");
    println!("    20, 21 FTP data transfer");
    println!("    22     SSH");
    println!("    53     DNS");
    println!("    80     HTTP");
    println!("    143    IMAP");
    println!("    443    HTTPS");
    println!("    445    SMB");
    println!("    465    SMTP");
    println!("    1080   Socks proxy");
    println!("    1194   OpenVPN");
    println!("    3306   MySQL");
    println!("    5432   PostgreSQL");
    println!("    7329   Docker proxy");
    println!("    9050   TOR proxy");
    println!("    9100   Printers default port");
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

fn check(ip: Vec<u8>, ports: Vec<u16>, threads: Arc<Mutex<usize>>, report: Arc<Mutex<Vec<String>>>, singleAddress: bool) {
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

        Ok(_sock) => {}
    }
    println!("[*] {} found responsive", ipToString(&ip));

    let open = Arc::new(Mutex::new(Vec::<u16>::new()));

    if singleAddress {
        let threadCount = thread::available_parallelism().unwrap().get();

        let portThreadPool = threadpool::ThreadPool::new(threadCount);
        let runningThreads = Arc::new(Mutex::new(0));

        let mut startPortIndex = 0;
        let portsChunk = if &threadCount > &ports.len() { 1 } else { &ports.len() / threadCount };

        while startPortIndex < (&ports.len()).to_owned() {
            let runningThreadsClone = runningThreads.clone();
            let openClone = open.clone();
            let portsClone = ports.clone();

            portThreadPool.exec(move || {
                *runningThreadsClone.lock().unwrap() += 1;

                for port in &portsClone[startPortIndex..startPortIndex + portsChunk] {
                    match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, *port as u16)), Duration::from_millis(100)) {

                        Ok(sock) => {
                            openClone.lock().unwrap().push(*port as u16);
                            sock.shutdown(Shutdown::Both);
                            println!("[*] Open port found: {}", port);
                        },

                        _ => {}
                    }
                }

                *runningThreadsClone.lock().unwrap() -= 1;
            });
            startPortIndex += portsChunk;
        }

        sleep(Duration::from_millis(100));

        while *runningThreads.lock().unwrap() > 0 {
            sleep(Duration::from_millis(100));
        }


    } else {
        for port in ports {
            match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, port)), Duration::from_millis(100)) {
                Ok(sock) => {
                    open.lock().unwrap().push(port as u16);
                    sock.shutdown(Shutdown::Both);
                    println!("[*] Open port found: {}", port);
                },
                _ => {}
            }
        }
    }



    report.lock().unwrap().push(format!(
        "[*] Found {} open ports: {:?}", ipToString(&ip), open.lock().unwrap().to_vec())
    );
    *threads.lock().unwrap() -= 1;
}

fn maskFromCidr(cidr: u8) -> Vec<u8> {
    let mut bits = Vec::<u8>::new();
    let mut mask = Vec::<u8>::new();

    for i in 0_u8..32_u8 {
        if i < cidr {
            bits.push(1_u8);
        } else {
            bits.push(0_u8)
        }
    }

    let mut index: usize = 0;
    while index < 32 {
        let mut chunk = bits[index..index+8].to_vec();
        chunk.reverse();

        let mut bit = 0;
        let mut byte = 0_u8;

        while bit < 8 {
            byte += chunk[bit] * 2_i32.pow(bit as u32) as u8;
            bit += 1;
        }

        mask.push(byte);
        index += 8;
    }

    return mask;
}

fn main() {
    let mut args = std::env::args().collect::<Vec::<String>>();
   
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        println!("rns: Rust Network Scan");
        println!("usage: rns [-s|--single] IPv4 [NETMASK] [OPTIONS]");
        println!("\noptions:");
        println!("    -std                         Only check standard ports");
        println!("    -s  | --single               Only check the specified address");
        println!("    -e  | --explain              Explain standard ports");
        println!("    -p  | --ports PORTS          List of ports to scam, comma separated");
        println!("    -pr | --ports-range PORTS    Range of ports, comma separated");
        println!("    -h  | --help                 Show this message and exit");
        println!("\nnotes:");
        println!("    NetMask can be specified in both IP address form");
        println!("    (e.g. 255.255.255.0) and CIDR form (e.g. 24)");
        println!("\nexamples:");
        println!("- scan the entire network");
        println!("    $ rns 192.168.1.0 255.255.255.0 -std");
        println!("    $ rns 192.168.1.0 24 -std");
        println!("- scan all ports on single address");
        println!("    $ rns -s 192.168.1.10");
        println!("- scan only ports in the range 1000-9999 on the entire network");
        println!("    $ rns 192.168.1.0 24 -pr 1000,9999");
        println!("- scan only certain ports on single address");
        println!("    $ rns -s 192.168.1.10 -p 80,8080,8088,8888,8808");

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
    
    let ports: Vec<u16>;
    let mut allPorts = false;

    if args.contains(&"-std".to_string()) {
        ports = STD_PORTS.clone().to_vec();
        
    } else if args.contains(&"--ports".to_string()) || args.contains(&"-p".to_string()) {
        let flagIndex = {
            let mut index: usize = 0;

            for arg in &args {
                if *arg == "--ports".to_string() || *arg == "-p".to_string() {
                    break
                }

                index += 1;
            }

            index
        };

        args.remove(flagIndex);
        ports = {
            let stringPorts = args.remove(flagIndex);
            let mut uPorts = Vec::<u16>::new();

            for port in stringPorts.split(",") {

                match port.parse::<u16>() {
                    Err(_) => {
                        println!("Error: port '{}' is not a valid port", port);
                    },
                    Ok(p) => {
                        uPorts.push(p);
                    }
                }
            }
            uPorts
        };
    } else if args.contains(&"-pr".to_string()) || args.contains(&"--ports-range".to_string()) {
        let flagIndex = {
            let mut index: usize = 0;

            for arg in &args {
                if *arg == "-pr".to_string() || *arg == "--ports-range".to_string() {
                    break
                }

                index += 1;
            }

            index
        };

        args.remove(flagIndex);
        ports = {
            let stringPorts = args.remove(flagIndex);
            let splitted = stringPorts.split(",").collect::<Vec<&str>>();
            println!("splitted : {:?}", &splitted);
            let startPort = match splitted.get(0).unwrap().parse::<u16>() {
                Err(_) => {
                    println!("Error: port '{}' is not a valid port", splitted[0]);
                    std::process::exit(0);
                },
                Ok(p) => p
            };

            let endPort = match splitted.get(1).unwrap().parse::<u16>() {
                Err(_) => {
                    println!("Error: port '{}' is not a valid port", splitted[1]);
                    std::process::exit(0);
                },
                Ok(p) => p
            };

            let mut range = Vec::<u16>::new();
            for port in startPort..endPort {
                range.push(port);
            }
            range
        };
    } else {
        allPorts = true;
        ports = {
            let mut temp = Vec::<u16>::new();

            for port in 0..65536 {
                temp.push(port as u16);
            }

            temp
        }
    }

    match args.iter().position(|str| *str == "-s".to_string() || *str == "--single".to_string()) {
        None => {},
        Some(index) => {
            args.remove(index);
            
            let threads = Arc::new(Mutex::new(0_usize));
            let report = Arc::new(Mutex::new(Vec::<String>::new()));
            
            let address = args.get(index).unwrap();
            println!("[*] Checking single IP {}", address);
            
            if !allPorts {
                println!("[*] Checking ports: {}\n", {
                    if &ports.len() < &20 {
                        format!("{:?}", &ports)
                    } else {
                        format!("[{} -> {}]", &ports.first().unwrap(), &ports.last().unwrap())
                    }
                });

            } else {
                println!("[*] Checking all ports (0-65535)\n");
            }

            check(makeu8Vec(address.to_owned()), ports, threads, Arc::clone(&report), true);
            println!("\n[*] Final report:\n");

            for line in &*report.lock().unwrap() {
                println!("{}", line);
            }

            std::process::exit(0);
        }
    }

    if args.len() < 3 {
        println!("Too few arguments");
        std::process::exit(0);
    }

    let ip = makeu8Vec(args[1].clone());
    let netmask = args[2].clone();

    let mask: Vec<u8>;
    if regex::Regex::new(r"([0-9]{1,3}\.){3}[0-9]{1,3}").unwrap().clone().is_match(netmask.as_str()) {
        mask = makeu8Vec(netmask);

    } else if regex::Regex::new(r"[0-9]{1,2}").unwrap().clone().is_match(netmask.as_str()) {
        mask = maskFromCidr(netmask.parse::<u8>().unwrap());

    } else {
        println!("Netmask must be in ip address form or in cidr form");
        std::process::exit(0);
    }

    let inverseMask = makeInverseMask(&mask);

    let baseIP = makeBaseIP(&ip, &mask);
    let endIP = makeEndIP(&ip, &inverseMask);

    println!("[*] Netmask: {}", ipToString(&mask));
    println!("[*] Hostmask: {}", ipToString(&inverseMask));

    println!("[*] Base IP: {}", ipToString(&baseIP));
    println!("[*] Broadcast IP: {}\n", ipToString(&endIP));

    if !allPorts {
        println!("[*] Checking ports: {}\n", {
            if &ports.len() < &20 {
                format!("{:?}", &ports)

            } else {
                format!("[{} -> {}]", &ports.first().unwrap(), &ports.last().unwrap())
            }
        });

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
        let portsClone = ports.clone();

        thread::spawn(move ||{
            check(ipClone, portsClone,
                  mutexClone, reportClone, false);
        });

        //thread::sleep(Duration::from_millis(25));
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
