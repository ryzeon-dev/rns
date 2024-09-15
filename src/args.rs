use crate::STD_PORTS;

#[derive(Debug)]
pub struct Args {
    pub ip: String,
    pub single: bool,
    pub mask: String,
    pub ports: Vec<u16>,
    pub local: bool,
    pub localProtocol: String,
    pub allPorts: bool,
    pub scanMac: bool,
    pub hostTimeout: u64,
    pub portTimeout: u64
}

impl Args {
    pub fn new() -> Args {
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

    pub fn parse(args: &mut Vec<String>) -> Args {
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
                            println!("Port '{}' is not a valid port", port);
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
                        println!("Port '{}' is not a valid port", splitted[0]);
                        std::process::exit(0);
                    },
                    Ok(p) => p
                };

                let endPort = match splitted.get(1).unwrap().parse::<u16>() {
                    Err(_) => {
                        println!("Port '{}' is not a valid port", splitted[1]);
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

                }
            } else {
                println!("Bad argument '{}' for option `--local`. Allowed values are: tcp, udp", &args[flagIndex + 1]);
                std::process::exit(1);
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
