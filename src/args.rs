use self::super::ports;
use regex::Regex;

#[derive(Debug)]
pub struct Args {
    pub scan: bool,

    pub ip: String,
    pub single: bool,
    pub mask: String,
    pub ports: Vec<u16>,
    pub scanMac: bool,
    pub hostTimeout: u64,
    pub portTimeout: u64,

    pub help: bool,
    pub explain: bool,

    pub list: bool,
    pub listPorts: bool,
    pub listProtocol: String,
    pub listAddresses: bool,
    pub listAddressType: String,

    pub json: bool,

    pub version: bool
}

impl Args {
    pub fn new() -> Args {
        Args {
            scan: false,
            ip: String::new(),
            single: false,
            mask: String::new(),
            ports: Vec::<u16>::new(),
            scanMac: false,
            hostTimeout: 1000,
            portTimeout: 100,

            help: false,
            explain: false,

            list: false,
            listPorts: false,
            listProtocol: String::new(),
            listAddresses: false,
            listAddressType: String::new(),

            json: false,

            version: false
        }
    }

    pub fn parse(args: &mut Vec<String>) -> Args {
        let mut arguments = Args::new();
        let mut index = 0_usize;

        let command = match args.get(index) {
            None => {
                eprintln!("Too few arguments");
                std::process::exit(1);
            },
            Some(cmd) => cmd.to_owned()
        };
        index += 1;

        if command == "scan".to_string() {
            arguments.scan = true;

            let following = match args.get(index) {
                None => {
                    eprintln!("Expected ip address or `single` command word after `scan`");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };
            let ip;

            if following == "single".to_string() {
                arguments.single = true;
                index += 1;

                ip = match args.get(index) {
                    None =>  {
                        eprintln!("Expected ip address after `single`");
                        std::process::exit(1);
                    },
                    Some(address) => address.to_owned()
                };

            } else {
                ip = following;
            }

            if Regex::new(r"([0-9]{1,3}\.){3}[0-9]{1,3}").unwrap().is_match(&ip) {
                arguments.ip = ip;

            } else {
                eprintln!("Bad ip address '{}'", ip);
                std::process::exit(1);
            }
            index += 1;

            let followingCommand = match args.get(index) {
                None => {
                    eprintln!("Expecting `mask` or `ports` after ip address");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };

            if followingCommand == "mask" {
                index += 1;
                if arguments.single {
                    eprintln!("Not expecting netmask when scanning single address");
                    std::process::exit(1);
                }

                let mask = match args.get(index) {
                    None => {
                        eprintln!("Expecting network mask after `mask`");
                        std::process::exit(1);
                    },
                    Some(str) => str.to_owned()
                };
                index += 1;

                if Regex::new(r"([0-9]{1,3}\.){3}[0-9]{1,3}").unwrap().is_match(&mask) ||
                    Regex::new(r"[0-9]{1,2}").unwrap().is_match(&mask) {
                    arguments.mask = mask;

                } else {
                    eprintln!("Bad netmask '{}'", mask);
                    std::process::exit(1);
                }

            } else if followingCommand != "mask" && !arguments.single {
                eprintln!("Expecting `mask` after ip address");
                std::process::exit(1);
            }

            let portsCommand = match args.get(index) {
                None => {
                    eprintln!("Expecting `ports` keyword");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };
            index += 1;

            if portsCommand != "ports".to_string() {
                eprintln!("Expecting `ports` keyword");
                std::process::exit(1);
            }

            let following = match args.get(index) {
                None => {
                    eprintln!("Expecting port specification after `ports`");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };
            index += 1;

            if following == "all".to_string() {
                arguments.ports = {
                    let mut ports = Vec::<u16>::new();

                    for port in 0..65536 {
                        ports.push(port as u16);
                    }

                    ports
                };
            } else if following == "std".to_string() {
                arguments.ports = Vec::from(ports::STD_PORTS);

            } else if following == "nmap".to_string() {
                arguments.ports = Vec::from(ports::NMAP_PORTS);

            } else if following.contains(",") {
                arguments.ports = {
                    let mut ports = Vec::<u16>::new();

                    for port in following.split(",") {
                        match port.parse::<u16>() {
                            Err(_) => {
                                eprintln!("Invalid port '{}'", port);
                                std::process::exit(1);
                            },
                            Ok(p) => {
                                ports.push(p)
                            }
                        }
                    }

                    ports
                }

            } else if following.contains("-") {
                arguments.ports = {
                    let mut ports = Vec::<u16>::new();

                    let splitted = following.split("-").collect::<Vec<&str>>();
                    let startPort = match splitted.get(0).unwrap().parse::<u16>() {
                        Err(_) => {
                            eprintln!("Invalid port range start");
                            std::process::exit(1);
                        },
                        Ok(p) => p
                    };

                    let endPort = match splitted.get(1) {
                        None => {
                            eprintln!("Missing port range end");
                            std::process::exit(1);
                        },

                        Some(p) => {
                            match p.parse::<u16>() {
                                Err(_) => {
                                    eprintln!("Invalid port range end");
                                    std::process::exit(1);
                                },
                                Ok(port) => port
                            }
                        }
                    };

                    for port in startPort..endPort {
                        ports.push(port);
                    }

                    ports
                }
            } else {
                eprintln!("Invalid port(s)");
                std::process::exit(1);
            }

            while index < args.len() {
                let command = args.get(index).unwrap().to_owned();
                index += 1;

                if command == "host-timeout" {
                    let following = match args.get(index) {
                        None => {
                            eprintln!("Expecting timeout after `host-timeout`");
                            std::process::exit(1);
                        },
                        Some(str) => str.to_owned()
                    };

                    arguments.hostTimeout = match following.parse::<u64>() {
                        Err(_) => {
                            eprintln!("Invalid value '{}' for `host-timeout`", following);
                            std::process::exit(1);
                        },
                        Ok(timeout) => timeout
                    };
                    index += 1;

                } else if command == "port-timeout" {
                    let following = match args.get(index) {
                        None => {
                            eprintln!("Expecting timeout after `port-timeout`");
                            std::process::exit(1);
                        },
                        Some(str) => str.to_owned()
                    };

                    arguments.portTimeout = match following.parse::<u64>() {
                        Err(_) => {
                            eprintln!("Invalid value '{}' for `port-timeout`", following);
                            std::process::exit(1);
                        },
                        Ok(timeout) => timeout
                    };
                    index += 1;

                } else if command == "scan-mac" {
                    arguments.scanMac = true;

                } else if command == "json"{
                    arguments.json = true;

                } else {
                    eprintln!("Unexpected command '{}'", command);
                    std::process::exit(1);
                }
            }

        } else if command == "list".to_string() {
            arguments.list = true;

            let following = match args.get(index) {
                None => {
                    eprintln!("Expecting either `ports` or `addresses` after `list`");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };

            index += 1;

            if following == "ports".to_string() {
                arguments.listPorts = true;

                if index < args.len() {
                    let protocol = args.get(index).unwrap().to_owned();

                    if ! ["tcp", "udp"].contains(&protocol.as_str()) {
                        eprintln!("Valid open ports protocols are: tcp, udp");
                        std::process::exit(1);

                    } else {
                        arguments.listProtocol = protocol;
                        index += 1;
                    }
                }

            } else if following == "addresses".to_string() {
                arguments.listAddresses = true;

            } else {
                eprintln!("Expecting either `ports` or `addresses` after `list`");
                std::process::exit(1);
            }

        } else if command == "help".to_string() {
            arguments.help = true;

        } else if command == "explain".to_string() {
            arguments.explain = true;

        } else if command == "version".to_string() {
            arguments.version = true;

        } else{
            eprintln!("Bad command '{}'. Run `rns help` for usage", command);
            std::process::exit(1);
        }

        if index < args.len() {
            eprintln!("Unexpected arguments '{}'", args[index..].join(" "));
            std::process::exit(1);
        }

        arguments
    }
}
