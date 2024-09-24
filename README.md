<div style="display: flex; flex-direction: row; justify-content: start">
    <img src="https://img.shields.io/badge/rust-16a085?style=for-the-badge&logo=rust" href="" style="margin: 10px" />
    <img src="https://img.shields.io/badge/tcp/ip-16a085?style=for-the-badge" href="" style="margin: 10px" />
    <img src="https://img.shields.io/badge/mac%20address-16a085?style=for-the-badge" href="" style="margin: 10px"/>
</div>

# rns - Rust Network Scan

- Network scanning tool written in rust 

## Installation
- precompiled binaries are available for linux\_amd64 and linux\_arm64 architectures, inside the `bin` folder, otherwise you have to compile from source
- package pre-requisites for local compilation:
```
git
cargo
make
```

### One-liner
```
git clone https://github.com/ryzeon-dev/rns && cd rns && make && sudo make install
```

### Step by step
- clone the repo
```
git clone https://github.com/ryzeon-dev/rns
```

- enter the `rns` directory

```
cd rns
```

- build the executable

```
make
```


- install (requires root)

```
sudo make install
```


## Usage
### Scanning
#### Network Scanning
- you must provide an IP address, a network mask (ip address or CIDR form) and some ports to scan
```
rns scan 192.168.1.0 mask 24 ports std
```

- it is possible to set the timeout (in milliseconds) for both host scanning (checking if the host is up) and port scanning (checking if the ports is open), using the `host-timeout` and `ports-timeout` verbs
```
rns scan 192.168.1.0 mask 255.255.255.0 ports std host-timeout 1500 ports-timeout 500
```

- to scan certain ports, write them comma separated after the `ports` verb
```
rns scan 192.168.1.0 mask 24 ports 80,8080,8088,8808,8888 
```

- to scan a port range (e.g. from 0 to 999), write the starting port and the ending port (plus one) separated by `-`
  - remember that the ending port is a limit, and therefore excluded 
```
rns scan 192.168.1.0 mask 24 ports 0-1000
```

- to scan the standard ports (you can get a description for them running `rns explain`) use `std` as argument for `ports` verb 
```
rns scan 192.168.1.0 mask 24 ports std
```

- to scan the nmap's standard 1000 ports, use `nmap` as argument for `ports` verb
```
rns scan 192.168.1.0 mask 24 ports nmap
```
#### Single address scanning
- to scan only one IP address, use the `single` verb before the IP address
  - note that network mask is not required (and must not be provided)
```
rns scan single 192.168.1.16 ports std
```

- all the verbs shown above are valid for single-address scanning 

### Listing
#### Locally open ports
- to list the ports openend on local machine, use the `list ports` verb, and both TCP and UDP open ports will be shown
```
rns list ports
```

- to only view TCP or UDP, pass `tcp` or `udp` after `ports` verb
```
rns list ports tcp
```

#### Local IP Addresses
- to list local machine's IP addresses use `list addresses` verb
```
rns list addresses
```

### Help 
- run `rns help` to get help

### Version
- version can be checked running `rns version`
