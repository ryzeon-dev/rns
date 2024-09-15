<div style="display: flex; flex-direction: row; justify-content: start">
    <img src="https://img.shields.io/badge/rust-16a085?style=for-the-badge&logo=rust" href="" style="margin: 10px" />
    <img src="https://img.shields.io/badge/tcp/ip-16a085?style=for-the-badge" href="" style="margin: 10px" />
    <img src="https://img.shields.io/badge/mac%20address-16a085?style=for-the-badge" href="" style="margin: 10px"/>
</div>

# rns - Rust Network Scan

- Network scanning tool written in rust 

## Installation
- requires the following packages to be installed:
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
- give any IP address from the network you want to scan, and the relative netmask (note that mask can be specified in both IP address and CIDR form)

```
rns 192.168.1.25 255.255.255.0
rns 192.168.1.25 24
```
- to only check the standard ports add `-std` flag
```
rns 192.168.1.25 255.255.255.0 -std
```

- to only check certain ports use the `-p` or `--ports` flag followed by the list of ports, comma separated
```
rns 192.168.1.25 24 -p 80,8080,8088,8808,8888
```

- to check a port range use the `-pr` or `--ports-range` flag, followed by the starting port and the ending port (which is excluded), comma separated
```
rns 192.168.1.25 24 -pr 1000,10000
```

- to find the MAC address of the responsive IPs, pass the `-m` or `--mac` flag
  - if ran as root, arp messages will be sent, otherwise cached macs will be used
```
rns 192.168.1.25 24 -std --mac
```

- to check locally open ports use the `-l` or `--local` flag
  - "tcp" or "udp" can be added as arguments, if missing both tcp and udp open ports will be shown
```
rns --local
rns -l tcp
```

- to check a single address run (any of the previous flags can be also used with a single address):
```
rns -s 192.168.1.10
```
- to get an explanation for the standard ports run :
```
rns --explain 
rns -e 
```
- to get help run 
```
rns --help
rns -h
```