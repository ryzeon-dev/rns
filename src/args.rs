use self::super::ports;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct Args {
    pub scan: bool,

    pub ip: String,
    pub single: bool,
    pub mask: String,
    pub ports: Vec<u16>,
    pub scanMac: bool,
    pub hostTimeout: u64,
    pub portTimeout: u64,
    pub macOnly: bool,

    pub help: bool,
    pub explain: bool,

    pub list: bool,
    pub listPorts: bool,
    pub listProtocol: String,
    pub listAddresses: bool,
    pub listInterfaces: bool,
    pub listRoutes: bool,
    pub listLocal: bool,

    pub monitor: bool,
    pub monitorInterface: String,
    pub displayBits: bool,

    pub set: bool,
    pub setInterface: bool,
    pub setInterfaceName: String,
    pub setInterfaceStatus: bool,
    pub setInterfaceStatusToBeSet: String,

    pub quiet: bool,
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
            macOnly: false,

            help: false,
            explain: false,

            list: false,
            listPorts: false,
            listProtocol: String::new(),
            listAddresses: false,
            listInterfaces: false,
            listRoutes: false,
            listLocal: false,

            monitor: false,
            monitorInterface: String::new(),
            displayBits: false,

            set: false,
            setInterface: false,
            setInterfaceName: String::new(),
            setInterfaceStatus: false,
            setInterfaceStatusToBeSet: String::new(),

            quiet: false,
            json: false,

            version: false
        }
    }

    fn checkFlags(argList: Vec<String>, arguments: &mut Args) -> Vec<String> {
        let mut args = argList;
        let mut index = 0_usize;

        while index < args.len() {
            let element = args.get(index).unwrap();


            if element.starts_with("--") {
                let flag = element.replace("--", "");

                if flag == "quiet" {
                    arguments.quiet = true;

                } else if flag == "json" {
                    arguments.json = true;

                } else if flag == "bit" {
                    arguments.displayBits = true;

                } else {
                    eprintln!("Unrecognized flag `--{}`", flag);
                    std::process::exit(1);
                }

                args.remove(index);

            } else if element.starts_with("-") {
                let letters = element.replace("-", "");

                for letter in letters.chars() {
                    if letter.to_string() == "q" {
                        arguments.quiet = true;

                    } else if letter.to_string() == "j" {
                        arguments.json = true;

                    } else if letter.to_string() == "b" {
                        arguments.displayBits = true;

                    } else {
                        eprintln!("Unrecognized flag `-{}`", letter);
                        std::process::exit(1);
                    }
                }

                args.remove(index);
            } else {
                index += 1;
            }

        }

        return args;
    }

    pub fn parse(argList: Vec<String>) -> Args {
        let mut arguments = Args::new();
        let mut index = 0_usize;

        let args = &mut Args::checkFlags(argList, &mut arguments);

        let command = match args.get(index) {
            None => {
                eprintln!("Too few arguments");
                std::process::exit(1);
            },
            Some(cmd) => cmd.to_owned()
        };
        index += 1;

        if command == "scan".to_string() || command == "s".to_string() {
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

            let followingCommand = match args.get(index) {
                None => {
                    eprintln!("Expecting `ports` or `mac-only` after ip address/mask");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };
            index += 1;

            if followingCommand == "ports".to_string() {
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

            } else if followingCommand == "mac-only" {
                arguments.macOnly = true;

            } else {
                eprintln!("Expecting `ports` or `mac-only` after ip address/mask, found `{}`", followingCommand);
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

                } else {
                    eprintln!("Unexpected command '{}'", command);
                    std::process::exit(1);
                }
            }

        } else if command == "list".to_string() || command == "l".to_string() {
            arguments.list = true;

            let following = match args.get(index) {
                None => {
                    eprintln!("Expecting either `ports`, `addresses`, `interfaces`, `routes` or `local` after `list`");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };

            index += 1;

            if following == "ports".to_string() || following == "p".to_string() {
                arguments.listPorts = true;

                if index < args.len() {
                    let protocol = args.get(index).unwrap().to_owned();

                    if !["tcp", "udp"].contains(&protocol.as_str()) {
                        eprintln!("Valid open ports protocols are: tcp, udp");
                        std::process::exit(1);
                    } else {
                        arguments.listProtocol = protocol;
                        index += 1;
                    }
                }
            } else if following == "addresses".to_string() || following == "a".to_string() {
                arguments.listAddresses = true;

            } else if following == "interfaces".to_string() || following == "i".to_string(){
                arguments.listInterfaces = true;

            } else if following == "routes".to_string() || following == "r".to_string() {
                arguments.listRoutes = true;

            } else if following == "local".to_string() || following == "l".to_string(){
                arguments.listLocal = true;

            } else {
                eprintln!("Expecting either `ports`, `addresses`, `interfaces`, `routes` or `local` after `list`");
                std::process::exit(1);
            }

        } else if command == "monitor".to_string() || command == "m".to_string() {
            arguments.monitor = true;

            let following = match args.get(index) {
                None => {
                    eprintln!("Expecting interface name after `monitor` verb");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };

            index += 1;
            arguments.monitorInterface = following;

        } else if command == "set".to_string() {
            arguments.set = true;

            let following = match args.get(index) {
                None => {
                    eprintln!("Expecting `interface` after `set` verb");
                    std::process::exit(1);
                },
                Some(str) => str.to_owned()
            };
            index += 1;

            if following == "interface".to_string() || following == "i".to_string() {
                arguments.setInterface = true;

                let following = match args.get(index) {
                    None => {
                        eprintln!("Expecting interface name after `interface` verb");
                        std::process::exit(1);
                    },
                    Some(str) => str.to_owned()
                };

                index += 1;
                arguments.setInterfaceName = following;

                let following = match args.get(index) {
                    None => {
                        eprintln!("Expecting `status` after interface name");
                        std::process::exit(1);
                    },
                    Some(str) => str.to_owned()
                };
                index += 1;

                if following == "status".to_string() || following == "s".to_string() {
                    arguments.setInterfaceStatus = true;

                    let following = match args.get(index) {
                        None => {
                            eprintln!("Expecting either `up` or `down` after `status` verb");
                            std::process::exit(1);
                        },
                        Some(str) => str.to_owned()
                    };
                    index += 1;

                    if ["up", "down"].contains(&following.as_str()) {
                        arguments.setInterfaceStatusToBeSet = following;

                    } else {
                        eprintln!("Expecting either `up` or `down` after `status` verb");
                        std::process::exit(1);
                    }

                } else {
                    eprintln!("Expecting `status` after interface name");
                    std::process::exit(1);
                }

            } else {
                eprintln!("Expecting `interface` after `set` verb");
                std::process::exit(1);
            }

        } else if command == "help".to_string() || command == "h".to_string() {
            arguments.help = true;

        } else if command == "explain".to_string() || command == "e".to_string() {
            arguments.explain = true;

        } else if command == "version".to_string() || command == "v".to_string() {
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
