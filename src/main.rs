#![allow(non_snake_case, unused_must_use, dead_code, unused_variables)]

mod threadpool;

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, Shutdown, Ipv4Addr};
use std::time::Duration;
use std::{fs, thread};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use regex;
use libarp;
use std::str::FromStr;

const VERSION: &str = "0.8.1";
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

    return uIP
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

fn check(ip: Vec<u8>, ports: Vec<u16>, threads: Arc<Mutex<usize>>, report: Arc<Mutex<Vec<String>>>, singleAddress: bool, hostTimeout: u64, portTimeout: u64, checkMac: bool) {
    *threads.lock().unwrap() += 1;

    let formattedIP = {[ip[0], ip[1], ip[2], ip[3]]};
    let addr = &SocketAddr::from((formattedIP, 80));

    match TcpStream::connect_timeout(
        addr,
        Duration::from_millis(hostTimeout)
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

                let range = if startPortIndex + portsChunk < portsClone.len() { portsClone[startPortIndex..startPortIndex + portsChunk].to_vec() } else { portsClone[startPortIndex..].to_vec() };
                for port in &range {
                    match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, *port)), Duration::from_millis(portTimeout)) {

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

            match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, port)), Duration::from_millis(portTimeout)) {
                Ok(sock) => {
                    open.lock().unwrap().push(port as u16);
                    sock.shutdown(Shutdown::Both);
                    println!("[*] {} Open port found: {}", ipToString(&ip), port);
                },
                _ => {}
            }
        }
    }

    let mac;
    if checkMac {
        mac = arpScanIp(ipToString(&ip));

    } else {
        mac = String::new();
    }

    report.lock().unwrap().push(format!(
        "[>] Found {}{} open ports: {:?}", ipToString(&ip),
        if mac.is_empty() { String::new() } else { format!(" ({})", mac) },
        open.lock().unwrap().to_vec())
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

fn arpScanIp<T: ToString>(ip: T) -> String {
    let mut arpClient;

    match libarp::client::ArpClient::new() {
        Err(_) => return String::new(),
        Ok(client) => { arpClient = client }
    }

    let res = arpClient.ip_to_mac(
        Ipv4Addr::from_str(ip.to_string().as_str()).unwrap(),
        Some(Duration::from_millis(100))
    );

    match res {
        Err(_) => String::new(),
        Ok(mac) => mac.to_string()
    }
}

fn hexByteToU8(hexa: &str) -> usize {
    let chars = hexa.chars().collect::<Vec<char>>();

    let first = {
        let char = chars[0] as usize;
        if char > 58 {
            char - 55
        } else {
            char  - 48
        }
    };

    let second = {
        let char = chars[1] as usize;
        if char > 58 {
            char - 55
        } else {
            char  - 48
        }
    };

    return first * 16 + second;
}

fn decodeAddress(address: String) -> String {
    let chunks = vec![
        &address[6..], &address[4..6], &address[2..4], &address[..2]
    ];

    let mut ip = String::new();
    for chunk in chunks {
        ip += format!("{}.", hexByteToU8(chunk)).as_str();
    }

    ip.remove(ip.len()-1);
    ip
}

fn decodePort(port: String) -> String {
    let chars = port.chars().collect::<Vec<char>>();

    let first = {
        let char = chars[0] as usize;
        if char > 58 {
            char - 55
        } else {
            char  - 48
        }
    };

    let second = {
        let char = chars[1] as usize;
        if char > 58 {
            char - 55
        } else {
            char  - 48
        }
    };

    let third = {
        let char = chars[2] as usize;
        if char > 58 {
            char - 55
        } else {
            char  - 48
        }
    };

    let fourth = {
        let char = chars[3] as usize;
        if char > 58 {
            char - 55
        } else {
            char  - 48
        }
    };

    return (first * 16 * 16 * 16 + second * 16 * 16 + third * 16 + fourth).to_string();
}

fn getUid() -> usize {
    let pid = std::process::id();
    fs::read_to_string(format!("/proc/{pid}/loginuid")).unwrap().parse::<usize>().unwrap()
}

fn removeBlanks(list: &mut Vec<&str>) -> Vec<String> {
    let mut new = Vec::<String>::new();

    for element in list {
        if !element.is_empty() {
            new.push(element.to_string());
        }
    }

    new
}

fn unpackLine(line: String) -> (String, String, String) {
    let splitted = removeBlanks(&mut line.split(" ").collect::<Vec<&str>>());

    let localPair = splitted.get(1).unwrap().split(":").collect::<Vec<&str>>();
    let listenAddress = decodeAddress((&localPair[0]).to_string());

    let listenPort = format!("{}", decodePort((&localPair[1]).to_string()));
    let inode = splitted.get(9).unwrap().trim().to_string();

    (listenAddress, listenPort, inode)
}

fn parseFile(filePath: String, tcp: bool) -> HashMap<String, (String, String)> {
    let mut map = HashMap::<String, (String, String)>::new();
    let file = fs::read_to_string(filePath).unwrap();

    for line in file.split("\n") {
        if line.is_empty() || !line.contains(":") {
            continue
        }

        let splittedLine = removeBlanks(&mut line.split(" ").collect::<Vec<&str>>());
        if (tcp && splittedLine[3] != "0A") || (!tcp && splittedLine[3] != "07") {
            continue
        }

        let (address, port, inode) = unpackLine(line.to_string());
        map.insert(inode, (address, port));
    }

    map
}

#[derive(Debug)]
struct Args {
    ip: String,
    single: bool,
    mask: String,
    ports: Vec<u16>,
    local: bool,
    localProtocol: String,
    allPorts: bool,
    scanMac: bool,
    hostTimeout: u64,
    portTimeout: u64
}

impl Args {
    fn new() -> Args {
        Args {
            ip: String::new(),
            single: false,
            mask: String::new(),
            ports: Vec::<u16>::new(),
            local: false,
            localProtocol: String::new(),
            allPorts: false,
            scanMac: false,
            hostTimeout: 1000,
            portTimeout: 100
        }
    }

    fn parse(args: &mut Vec<String>) -> Args {
        let mut arguments = Args::new();

        if args.contains(&"-std".to_string()) {
            arguments.ports = STD_PORTS.clone().to_vec();

        } else if args.contains(&"--ports".to_string()) || args.contains(&"-p".to_string()) {
            let flagIndex = {
                let mut index: usize = 0;

                for arg in &mut *args {
                    if *arg == "--ports".to_string() || *arg == "-p".to_string() {
                        break
                    }

                    index += 1;
                }

                index
            };

            args.remove(flagIndex);
            arguments.ports = {
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

                for arg in &mut *args {
                    if *arg == "-pr".to_string() || *arg == "--ports-range".to_string() {
                        break
                    }

                    index += 1;
                }
                index
            };

            args.remove(flagIndex);
            arguments.ports = {
                let stringPorts = args.remove(flagIndex);
                let splitted = stringPorts.split(",").collect::<Vec<&str>>();

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
        } else if args.contains(&"-l".to_string()) || args.contains(&"--local".to_string()) {
            arguments.local = true;

            let flagIndex = {
                let mut index: usize = 0;

                for arg in &mut *args {
                    if *arg == "-l".to_string() || *arg == "--local".to_string() {
                        break
                    }

                    index += 1;
                }
                index
            };

            if flagIndex == args.len() - 1 {

            } else if ["tcp", "udp"].contains(&args[flagIndex + 1].as_str()) {
                let protocol = args[flagIndex + 1].as_str();

                if protocol == "tcp" {
                    arguments.localProtocol = "tcp".to_string();

                } else if protocol == "udp" {
                    arguments.localProtocol = "udp".to_string();

                } else {
                    println!("Error: wrong argument for flag `--local`. Allowed values are: tcp, udp");
                    std::process::exit(1);
                }
            }

        } else {
            arguments.allPorts = true;
            arguments.ports = {
                let mut temp = Vec::<u16>::new();

                for port in 0..65536 {
                    temp.push(port as u16);
                }

                temp
            }
        }

        if args.contains(&"-ht".to_string()) || args.contains(&"--host-timeout".to_string()) {
            let flagIndex = {
                let mut index: usize = 0_usize;

                for arg in &mut *args {
                    if *arg == "-ht".to_string() || *arg == "--host-timeout".to_string() {
                        break
                    }
                    index += 1;
                }

                index
            };

            args.remove(flagIndex);
            arguments.hostTimeout = args.remove(flagIndex).parse::<u64>().unwrap();

        } else {
            arguments.hostTimeout = 1000_u64;
        }

        if args.contains(&"-pt".to_string()) || args.contains(&"--port-timeout".to_string()) {
            let flagIndex = {
                let mut index: usize = 0_usize;

                for arg in &mut *args {
                    if *arg == "-pt".to_string() || *arg == "--port-timeout".to_string() {
                        break
                    }
                    index += 1;
                }

                index
            };

            args.remove(flagIndex);
            arguments.portTimeout = args.remove(flagIndex).parse::<u64>().unwrap();

        } else {
            arguments.portTimeout = 100_u64;
        }

        if args.contains(&"-m".to_string()) || args.contains(&"--mac".to_string()) {

            let flagIndex = {
                let mut index: usize = 0_usize;
                for arg in &mut *args {
                    if *arg == "-m".to_string() || *arg == "--mac".to_string() {
                        break
                    }
                    index += 1;
                }
                index
            };

            args.remove(flagIndex);
            arguments.scanMac = true;

        } else {
            arguments.scanMac = false;
        }

        if args.contains(&"-s".to_string()) || args.contains(&"--single".to_string()) {
            let flagIndex = {
                let mut index = 0_usize;

                for arg in &mut *args {
                    if *arg == "-s".to_string() || *arg == "--single".to_string() {
                        break;
                    }
                    index += 1;
                }
                index
            };

            args.remove(flagIndex);
            arguments.single = true;
        }

        if args.get(1) != None {
            arguments.ip = args.get(1).unwrap().to_string();
        }

        if args.get(2) != None {
            arguments.mask = args.get(2).unwrap().to_string();
        }

        arguments
    }
}

fn main() {
    let mut args = std::env::args().collect::<Vec::<String>>();

    if args.len() == 1 {
        println!("Not enough arguments");
        std::process::exit(1);
    }

    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        println!("rns: Rust Network Scan version {VERSION}");
        println!("usage: rns [-s|--single] IPv4 [NETMASK] [OPTIONS]");
        println!("\noptions:");
        println!("    -e  | --explain                  Explain standard ports");
        println!("    -h  | --help                     Show this message and exit");
        println!("    -ht | --host-timeout TIMEOUT     Time to wait for host to answer (milliseconds), default 1000");
        println!("    -l  | --local [PROTO]            Display open ports on local machine, can be restricted to a certain protocol");
        println!("    -m  | --mac                      Scan MAC address if possible (requires root)");
        println!("    -p  | --ports PORTS              List of ports to scam, comma separated");
        println!("    -pr | --ports-range PORTS        Range of ports to scan, comma separated");
        println!("    -pt | --port-timeout TIMEOUT     Port scanning timeout (milliseconds), default 100");
        println!("    -s  | --single                   Only check the specified address");
        println!("    -std                             Only check standard ports");
        println!("    -v  | --version                  Display version and exit");
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
        println!("- display locally open tcp ports");
        println!("    $ rns -l tcp");
        println!("- displat all locally open ports");
        println!("    $ rns --local");

        std::process::exit(0);
    }

    if args.contains(&"-v".to_string()) || args.contains(&"--version".to_string()) {
        println!("version: {VERSION}");
        std::process::exit(0);
    }
    
    if args.contains(&"-e".to_string()) || args.contains(&"--explain".to_string()) {
        explainPorts();
        std::process::exit(0);
    }
    
    let arguments = Args::parse(&mut args);

    if arguments.local {
        let tcpMap = parseFile("/proc/net/tcp".to_string(), true);
        let udpMap = parseFile("/proc/net/udp".to_string(), false);

        let uid = getUid();

        if arguments.localProtocol == String::from("tcp") {
            if uid == 1000 {

                println!("{:15} : {:5}", "ADDRESS", "PORT");
                for (inode, (address, port)) in tcpMap {
                    println!("{:15} : {:5}", address, port);
                }
            }

        } else if arguments.localProtocol == String::from("udp") {
            if uid == 1000 {

                println!("{:15} : {:5}", "ADDRESS", "PORT");
                for (inode, (address, port)) in udpMap {
                    println!("{:15} : {:5}", address, port);
                }
            }

        } else {
            if uid == 1000 {
                println!("{:15} : {:5}", "ADDRESS", "PORT");
                println!("TCP");

                for (inode, (address, port)) in tcpMap {
                    println!("{:15} : {:5}", address, port);
                }

                println!("UDP");
                for (inode, (address, port)) in udpMap {
                    println!("{:15} : {:5}", address, port);
                }
            }
        }

        std::process::exit(0);
    }

    if arguments.single {
        let threads = Arc::new(Mutex::new(0_usize));
        let report = Arc::new(Mutex::new(Vec::<String>::new()));

        println!("[*] Checking single IP {}", arguments.ip);

        if !arguments.allPorts {
            println!("[*] Checking ports: {}\n", {
                if &arguments.ports.len() < &20 {
                    format!("{:?}", &arguments.ports)
                } else {
                    format!("[{} -> {}]", &arguments.ports.first().unwrap(), &arguments.ports.last().unwrap())
                }
            });

        } else {
            println!("[*] Checking all ports (0-65535)\n");
        }

        check(makeu8Vec(arguments.ip.to_owned()), arguments.ports, threads, Arc::clone(&report), true, arguments.hostTimeout, arguments.portTimeout, arguments.scanMac);
        println!("\n[*] Final report:\n");

        for line in &*report.lock().unwrap() {
            println!("{}", line);
        }

        std::process::exit(0);
    }

    let ip = makeu8Vec(arguments.ip.to_owned());
    let netmask = arguments.mask;

    let mask: Vec<u8>;
    if regex::Regex::new(r"([0-9]{1,3}\.){3}[0-9]{1,3}").unwrap().clone().is_match(netmask.as_str()) {
        mask = makeu8Vec(netmask.to_owned());

    } else if regex::Regex::new(r"[0-9]{1,2}").unwrap().clone().is_match(netmask.as_str()) {
        mask = maskFromCidr(netmask.parse::<u8>().unwrap());

    } else {
        println!("Netmask must be in ip address form or in cidr form");
        std::process::exit(1);
    }

    let inverseMask = makeInverseMask(&mask);

    let baseIP = makeBaseIP(&ip, &mask);
    let endIP = makeEndIP(&ip, &inverseMask);

    println!("[*] Netmask: {}", ipToString(&mask));
    println!("[*] Hostmask: {}", ipToString(&inverseMask));

    println!("[*] Base IP: {}", ipToString(&baseIP));
    println!("[*] Broadcast IP: {}\n", ipToString(&endIP));

    if !arguments.allPorts {
        println!("[*] Checking ports: {}\n", {
            if &arguments.ports.len() < &20 {
                format!("{:?}", &arguments.ports)

            } else {
                format!("[{} -> {}]", &arguments.ports.first().unwrap(), &arguments.ports.last().unwrap())
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
        let portsClone = arguments.ports.clone();

        thread::spawn(move ||{
            check(
                ipClone, portsClone, mutexClone, reportClone,
                false, arguments.hostTimeout, arguments.portTimeout, arguments.scanMac
            );
        });

        current = increment(&current);
    }

    while *threads.lock().unwrap() != 0_usize {
        sleep(Duration::from_millis(100));
    }

    println!("\n[*] Final report:\n");

    println!("[>] Netmask: {}", ipToString(&mask));
    println!("[>] Hostmask: {}", ipToString(&inverseMask));

    println!("[>] Base IP: {}", ipToString(&baseIP));
    println!("[>] Broadcast IP: {}\n", ipToString(&endIP));

    for line in &*report.lock().unwrap() {
        println!("{}", line);
    }
}