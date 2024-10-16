#![allow(non_snake_case, unused_must_use, dead_code, unused_variables)]

mod threadpool;
pub mod ports;
pub mod args;
mod ipv4Utils;
mod utils;
mod routeUtils;

use std::net::{SocketAddr, TcpStream, Shutdown, Ipv4Addr};
use std::time::Duration;
use std::{thread};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use regex;
use libarp;
use sysutil;
use rsjson;
use rsjson::{Node, NodeContent};
use ipv4Utils::{*};
use utils::{*};
use crate::routeUtils::getRoutes;

const VERSION: &str = "0.10.1";

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
    println!("    3389   Microsoft Windows Remote Desktop");
    println!("    5432   PostgreSQL");
    println!("    7329   Docker proxy");
    println!("    9050   TOR proxy");
    println!("    9100   Printers default port");
    println!("    51820  Wireguard VPN");
    println!("!!! These ports are usually assigned to these functions, but they might have been reassigned");
}

fn check(
    ip: Vec<u8>, threads: Arc<Mutex<usize>>, report: Arc<Mutex<Vec<String>>>,
    jsonReport: Arc<Mutex<rsjson::Json>>, arguments: args::Args) {
    *threads.lock().unwrap() += 1;

    let formattedIP = {[ip[0], ip[1], ip[2], ip[3]]};
    let addr = &SocketAddr::from((formattedIP, 80));

    match TcpStream::connect_timeout(
        addr,
        Duration::from_millis(arguments.hostTimeout)
    ) {
        Err(why) => {
            match why.kind() {
                std::io::ErrorKind::ConnectionRefused => {},
                _ => {
                    if !arguments.quiet && !arguments.json {
                        println!("[x] {} non responsive", ipToString(&ip));
                    }

                    *threads.lock().unwrap() -= 1;
                    return
                }
            }
        },

        Ok(_sock) => {}
    }

    if !arguments.json && !arguments.quiet {
        println!("[*] {} found responsive", ipToString(&ip));
    }

    let open = Arc::new(Mutex::new(Vec::<u16>::new()));

    if !arguments.macOnly {
        if !arguments.single {
            let threadCount = thread::available_parallelism().unwrap().get();

            let portThreadPool = threadpool::ThreadPool::new(threadCount);
            let runningThreads = Arc::new(Mutex::new(0));

            let mut startPortIndex = 0;
            let portsChunk = if &threadCount > &arguments.ports.len() { 1 } else { &arguments.ports.len() / threadCount };

            while startPortIndex < (&arguments.ports.len()).to_owned() {
                let runningThreadsClone = runningThreads.clone();
                let openClone = open.clone();
                let portsClone = arguments.ports.clone();

                portThreadPool.exec(move || {
                    *runningThreadsClone.lock().unwrap() += 1;

                    let range = if startPortIndex + portsChunk < portsClone.len() { portsClone[startPortIndex..startPortIndex + portsChunk].to_vec() } else { portsClone[startPortIndex..].to_vec() };
                    for port in &range {
                        match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, *port)), Duration::from_millis(arguments.portTimeout)) {

                            Ok(sock) => {
                                openClone.lock().unwrap().push(*port as u16);
                                sock.shutdown(Shutdown::Both);

                                if !arguments.quiet && !arguments.json {
                                    println!("[*] Open port found: {}", port);
                                }
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
            for port in arguments.ports {

                match TcpStream::connect_timeout(&SocketAddr::from((formattedIP, port)), Duration::from_millis(arguments.portTimeout)) {
                    Ok(sock) => {
                        open.lock().unwrap().push(port as u16);
                        sock.shutdown(Shutdown::Both);
                        if !arguments.quiet && !arguments.json {
                            println!("[*] {} Open port found: {}", ipToString(&ip), port);
                        }
                    },
                    _ => {}
                }
            }
        }
    }

    let stringedIp = ipToString(&ip);
    let mut mac;

    if arguments.scanMac || arguments.macOnly {
        mac = arpScanIp(&stringedIp);

        if mac.is_empty() {
            mac = getCachedArpMac(stringedIp.clone());
        }

    } else {
        mac = String::new();
    }

    let mut binding = jsonReport.lock().unwrap();
    let jsonNode = binding.get(&stringedIp);

    if jsonNode != None {
        for port in open.lock().unwrap().to_vec() {
            jsonNode.unwrap().toList().unwrap().push(rsjson::NodeContent::Int(port as usize));
        }

    } else {
        let mut content = rsjson::Json::new();
        content.addNode(Node::new("mac", NodeContent::String(mac.clone())));

        content.addNode(Node::new("ports", NodeContent::List({
            let mut ports = Vec::<NodeContent>::new();

            for port in open.lock().unwrap().to_vec() {
                ports.push(NodeContent::Int(port as usize));
            }

            ports
        })));

        let node = rsjson::Node::new(
            &stringedIp,
            NodeContent::Json(content)
        );

        binding.addNode(node);
    }

    if arguments.macOnly {
        report.lock().unwrap().push(format!(
                "[>] Found {}: mac {}", stringedIp,
                if mac.is_empty() { String::from("not found") } else { format!("{}", mac) },
            )
        );

    } else {
        report.lock().unwrap().push(format!(
                "[>] Found {}{} open ports: {:?}", stringedIp,
                if mac.is_empty() { String::new() } else { format!(" ({})", mac) },
                open.lock().unwrap().to_vec()
            )
        );
    }

    *threads.lock().unwrap() -= 1;
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

fn getCachedArpMac<T: ToString>(targetIp: T) -> String {
    let procNetArp = match std::fs::read_to_string("/proc/net/arp") {
        Ok(arp) => arp,
        Err(_) => return String::new()
    };

    for line in procNetArp.split("\n") {
        if !line.contains(".") {
            continue
        }

        let splitted = removeBlanks(&mut line.split(" ").collect::<Vec<&str>>());
        let ip = splitted.get(0).unwrap().to_owned();
        let mac = splitted.get(3).unwrap().to_owned();

        if ip == targetIp.to_string() {
            return mac;
        }
    }

    return String::new();
}

fn listCommand(arguments: args::Args) {
    if arguments.listPorts {

        let tcpMap = parseFile("/proc/net/tcp".to_string(), true);
        let udpMap = parseFile("/proc/net/udp".to_string(), false);

        if arguments.json {
            let mut json = rsjson::Json::new();

            if arguments.listProtocol == String::from("tcp") {
                let mut tcpNodes = Vec::new();

                for (inode, (address, port)) in tcpMap {
                    let mut nodeContent = rsjson::Json::new();

                    nodeContent.addNode(Node::new(
                        "address",
                        NodeContent::String(address)
                    ));

                    nodeContent.addNode(Node::new(
                        "port",
                        NodeContent::Int(port.parse::<usize>().unwrap())
                    ));

                    tcpNodes.push(NodeContent::Json(nodeContent));
                }

                json.addNode(Node::new(
                    "tcp",
                    NodeContent::List(tcpNodes)
                ));

            } else if arguments.listProtocol == String::from("udp") {
                let mut udpNodes = Vec::new();

                for (inode, (address, port)) in tcpMap {
                    let mut nodeContent = rsjson::Json::new();

                    nodeContent.addNode(Node::new(
                        "address",
                        NodeContent::String(address)
                    ));

                    nodeContent.addNode(Node::new(
                        "port",
                        NodeContent::Int(port.parse::<usize>().unwrap())
                    ));

                    udpNodes.push(NodeContent::Json(nodeContent));
                }

                json.addNode(Node::new(
                    "udp",
                    NodeContent::List(udpNodes)
                ));

            } else if arguments.listProtocol.is_empty() {
                let mut tcpNodes = Vec::new();

                for (inode, (address, port)) in tcpMap {
                    let mut nodeContent = rsjson::Json::new();

                    nodeContent.addNode(Node::new(
                        "address",
                        NodeContent::String(address)
                    ));

                    nodeContent.addNode(Node::new(
                        "port",
                        NodeContent::Int(port.parse::<usize>().unwrap())
                    ));

                    tcpNodes.push(NodeContent::Json(nodeContent));
                }

                json.addNode(Node::new(
                    "tcp",
                    NodeContent::List(tcpNodes)
                ));

                let mut udpNodes = Vec::new();

                for (inode, (address, port)) in udpMap {
                    let mut nodeContent = rsjson::Json::new();

                    nodeContent.addNode(Node::new(
                        "address",
                        NodeContent::String(address)
                    ));

                    nodeContent.addNode(Node::new(
                        "port",
                        NodeContent::Int(port.parse::<usize>().unwrap())
                    ));

                    udpNodes.push(NodeContent::Json(nodeContent));
                }

                json.addNode(Node::new(
                    "udp",
                    NodeContent::List(udpNodes)
                ));
            }

            println!("{}", json.toString());

        } else {
            if arguments.listProtocol == String::from("tcp") {
                println!("{:15} : {:5}", "ADDRESS", "PORT");
                for (inode, (address, port)) in tcpMap {
                    println!("{:15} : {:5}", address, port);
                }

            } else if arguments.listProtocol == String::from("udp") {
                println!("{:15} : {:5}", "ADDRESS", "PORT");
                for (inode, (address, port)) in udpMap {
                    println!("{:15} : {:5}", address, port);
                }

            } else if arguments.listProtocol.is_empty() {
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

    } else if arguments.listAddresses {
        let addresses = sysutil::getIPv4();

        if arguments.json {
            let mut json = rsjson::Json::new();

            for address in addresses  {
                let mut nodeContent = rsjson::Json::new();

                nodeContent.addNode(Node::new(
                    "cidr",
                    NodeContent::Int(address.cidr.parse::<usize>().unwrap())
                ));

                nodeContent.addNode(Node::new(
                    "interface",
                    NodeContent::String(address.interface)
                ));

                json.addNode(Node::new(
                    address.address,
                    NodeContent::Json(nodeContent)
                ));
            }

            println!("{}", json.toString());

        } else {
            for address in addresses {
                println!("{}/{} -> {}", address.address, address.cidr, address.interface);
            }
        }

    } else if arguments.listInterfaces {
        let interfaces = sysutil::networkInterfaces();

        if arguments.json {
            let mut json = rsjson::Json::new();

            for interface in interfaces {
                let mut nodeContent = rsjson::Json::new();

                nodeContent.addNode(Node::new(
                    "mac",
                    NodeContent::String(interface.macAddress)
                ));

                nodeContent.addNode(Node::new(
                    "type",
                    NodeContent::String(match interface.interfaceType {
                        sysutil::InterfaceType::Virtual => "virtual",
                        sysutil::InterfaceType::Physical => "physical",
                    }.to_string())
                ));

                json.addNode(Node::new(
                    interface.name,
                    NodeContent::Json(nodeContent)
                ));
            }
            println!("{}", json.toString());

        } else {
            for interface in interfaces {
                println!("{} -> {} ({} interface)", interface.name, interface.macAddress, match interface.interfaceType {
                    sysutil::InterfaceType::Virtual => "virtual",
                    sysutil::InterfaceType::Physical => "physical",
                });
            }
        }

    } else if arguments.listRoutes {
        let routes = getRoutes();

        if arguments.json {
            let mut json = rsjson::Json::new();
            let mut routesList = Vec::new();

            for route in routes {
                let mut nodeContent = rsjson::Json::new();

                nodeContent.addNode(Node::new(
                    "interface",
                    NodeContent::String(route.0)
                ));

                nodeContent.addNode(Node::new(
                    "destination",
                    NodeContent::String(route.1)
                ));

                nodeContent.addNode(Node::new(
                    "gateway",
                    NodeContent::String(route.2)
                ));

                nodeContent.addNode(Node::new(
                    "mask",
                    NodeContent::String(route.4)
                ));

                nodeContent.addNode(Node::new(
                    "metric",
                    NodeContent::Int(route.3.parse::<usize>().unwrap())
                ));

                routesList.push(NodeContent::Json(nodeContent));
            }

            json.addNode(Node::new(
                "routes",
                NodeContent::List(routesList)
            ));

            println!("{}", json.toString());

        } else {
            for route in routes {
                println!("iface {} {} -> {} mask {} metric {}", route.0, route.1, route.2, route.4, route.3);
            }
        }
    }
}

fn printHelp() {
    println!("rns: Rust Network Scan version {VERSION}");
    println!("usage: rns (scan | list | help | version | explain)");
    println!("    rns scan [single] IP [mask NETMASK] (ports (std | nmap | RANGE | LIST | all) | mac-only) [scan-mac] [host-timeout TIMEOUT] [port-timeout TIMEOUT] [FLAGS]");
    println!("    rns list [ports [tcp | udp] | addresses | interfaces | routes] [-j | --json]");
    println!("    rns help");
    println!("    rns version");
    println!("    rns explain");
    println!("flags: ");
    println!("    -j | --json     Output in json format");
    println!("    -q | --quiet    Only output final reports");
    println!("notes: ");
    println!("- main verbs, such as `scan`, `list`, `version`, `explain` can be called by their initial too");
    println!("- NETMASK can be specified both in ip address (255.255.255.0) and CIDR (24) form");
    println!("- ports RANGE must be '-' separated (e.g. 0-1000)");
    println!("- ports LIST must be ',' separated (e.g. 80,88,8080,8088,8808,8888)");
    println!("- `std` ports can be viewed running `rns explain`");
    println!("- `nmap` ports are the nmap's standard 1000 ports");
    println!("examples:");
    println!("- scan all ip addresses in 192.168.1.0/24 subnet, checking for standard ports and mac addresses");
    println!("    $ rns scan 192.168.1.0 mask 255.255.255.0 ports std scan-mac");
    println!("- scan a single ip addresses, checking for ports in range 0-1000");
    println!("    $ rns scan single 192.168.1.1 ports 0-1000");
    println!("- display locally open tcp ports");
    println!("    $ rns list ports tcp");
    println!("- display all local ip addresses");
    println!("    $ rns list addresses");
}

fn main() {
    let uid = getUid();
    let args = std::env::args().collect::<Vec::<String>>();

    if args.len() == 1 {
        eprintln!("Not enough arguments");
        std::process::exit(1);
    }

    let arguments = args::Args::parse(args[1..].to_vec());

    if arguments.help {
        printHelp();
        std::process::exit(0);
    }

    if arguments.version {
        println!("version: {VERSION}");
        std::process::exit(0);
    }

    if arguments.explain {
        explainPorts();
        std::process::exit(0);
    }

    if arguments.list {
        listCommand(arguments);
        std::process::exit(0);
    }

    if arguments.single {
        let threads = Arc::new(Mutex::new(0_usize));
        let report = Arc::new(Mutex::new(Vec::<String>::new()));
        let jsonReport = Arc::new(Mutex::new(rsjson::Json::new()));

        if !arguments.quiet && (!arguments.json || arguments.macOnly) {
            println!("[*] Checking single IP {}", arguments.ip);

            if arguments.ports.len() != 65536 {
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
        }

        check(
            makeu8Vec(arguments.ip.to_owned()), threads, Arc::clone(&report),
            Arc::clone(&jsonReport), arguments.clone()
        );

        if arguments.json {
            println!("{}", jsonReport.lock().unwrap().toString());

        } else {
            if !arguments.single {
                println!("\n[*] Final report:\n");
            }

            for line in &*report.lock().unwrap() {
                println!("{}", line);
            }
        }

        std::process::exit(0);
    }

    let ip = makeu8Vec((&arguments).ip.clone());
    let netmask = &arguments.mask;

    let mask: Vec<u8>;
    if regex::Regex::new(r"([0-9]{1,3}\.){3}[0-9]{1,3}").unwrap().clone().is_match(netmask.as_str()) {
        mask = makeu8Vec(netmask.to_owned());

    } else if regex::Regex::new(r"[0-9]{1,2}").unwrap().clone().is_match(netmask.as_str()) {
        mask = maskFromCidr(netmask.parse::<u8>().unwrap());

    } else {
        eprintln!("Netmask must be in ip address form or in cidr form");
        std::process::exit(1);
    }

    let inverseMask = makeInverseMask(&mask);

    let baseIP = makeBaseIP(&ip, &mask);
    let endIP = makeEndIP(&ip, &inverseMask);

    if !&arguments.quiet  && !&arguments.json {
        println!("[*] Netmask: {}", ipToString(&mask));
        println!("[*] Hostmask: {}", ipToString(&inverseMask));

        println!("[*] Base IP: {}", ipToString(&baseIP));
        println!("[*] Broadcast IP: {}\n", ipToString(&endIP));

        if !arguments.macOnly {
            if (&arguments).ports.len() != 65536 {
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
        }
    }

    let mut current = baseIP.clone();
    let threads = Arc::new(Mutex::new(0_usize));

    let report = Arc::new(Mutex::new(Vec::<String>::new()));
    let jsonReport = Arc::new(Mutex::new(rsjson::Json::new()));

    while current != endIP {
        let ipClone = current.clone();
        let mutexClone = Arc::clone(&threads);

        let reportClone = Arc::clone(&report);
        let jsonReportClone = Arc::clone(&jsonReport);
        let argumentsClone = arguments.clone();

        thread::spawn(move ||{
            check(
                ipClone, mutexClone, reportClone, jsonReportClone, argumentsClone
            );
        });

        current = increment(&current);
    }

    while *threads.lock().unwrap() != 0_usize {
        sleep(Duration::from_millis(100));
    }

    if arguments.json {
        println!("{}", jsonReport.lock().unwrap().toString());

    } else {
        if !arguments.quiet {
            println!("\n[*] Final report:\n");
        }

        println!("[>] Netmask: {}", ipToString(&mask));
        println!("[>] Hostmask: {}", ipToString(&inverseMask));

        println!("[>] Base IP: {}", ipToString(&baseIP));
        println!("[>] Broadcast IP: {}\n", ipToString(&endIP));

        for line in &*report.lock().unwrap() {
            println!("{}", line);
        }
    }
}