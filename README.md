<div style="display: flex; flex-direction: row; justify-content: start">
    <img src="https://img.shields.io/badge/rust-16a085?style=for-the-badge&logo=rust" href="" style="margin: 10px" />
    <img src="https://img.shields.io/badge/python3-16a085?style=for-the-badge&logo=python" href="" style="margin: 10px" />
    <img src="https://img.shields.io/badge/tcp/ip-16a085?style=for-the-badge" href="" style="margin: 10px" />
    <img src="https://img.shields.io/badge/mac%20address-16a085?style=for-the-badge" href="" style="margin: 10px"/>
    <img src="https://img.shields.io/badge/network%20interfaces-16a085?style=for-the-badge" href="" style="margin: 10px"/>
    <img src="https://img.shields.io/badge/open%20ports-16a085?style=for-the-badge" href="" style="margin: 10px"/>
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

## Install from Cargo
```
cargo install rns
```

## Compile and install
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

## Install precompiled
### `amd64`
```
sudo make install-amd64
```

### `arm64`
```
sudo make install-arm64
```

## GUI
- a GUI application written in Python3 is available
- the gui allows to execute `scan` and `list` actions
  - after inserting the required parameters, the relative `rns` command will be displayed
  - pressing the `run` button, the command will be executed, and its result displayed

### Compile
- from the `rns` directory, run
```
make compile-gui
```

### Install
- if you just compiled it, run
```
sudo make install-gui
```
- if you want to install a precompiled binary, run
```
sudo make install-gui-amd64
```
or 
```
sudo make install-gui-arm64
```

### Run
- run the command 
```
rns-gui
```

## Usage
### Scanning
- `scan` verb can be called by its initial too
```
rns s 192.168.1.0 mask 24 ports all
```

#### Network Scanning
- when scanning for IP addresses, `rns` will try to resolve the ip address into the host name, using the NetBIOS protocol
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

- to scan both open ports and mac addresses add `scan-mac` verb at the end
```
rns scan 192.168.1.0 mask 24 ports std scan-mac
```

- only scan for mac addresses use `mac-only` verb instead of `ports`
```
rns scan 192.168.1.0 mask 24 mac-only
```

- to scan the nmap's standard 1000 ports, use `nmap` as argument for `ports` verb
```
rns scan 192.168.1.0 mask 24 ports nmap
```

- to export the scan into a Json file, use the `--json` or `-j` flag
  - by doing so, all the stdout-communications are suppressed
```
rns scan 192.168.1.0 mask 24 ports std -j > report.json
```

- to have a quiet execution, use the `--quiet` or `-q` flag, this will output only the final report
```
rns scan 192.168.1.0 mask 24 ports std -q
```

#### Single address scanning
- to scan only one IP address, use the `single` verb before the IP address
  - note that network mask is not required (and must not be provided)
```
rns scan single 192.168.1.16 ports std
```

- all the verbs shown above are valid for single-address scanning 

### Listing
- `list` verb can be called by its initial too
```
rns l interfaces
```

- to export the listing into a Json file, use the `--json` or `-j` flag
```
rns list ports -j > report.json
```

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

#### Local Network Interfaces
- to list local machine's network interfaces use `list interfaces` verb
```
rns list interfaces
```

### All Local Machine Network Data
- lists network interface, and for each displays mac address, ipv4 and route(s)
```
rns list local
```

### Monitoring 
- to monitor an interface's activity use `monitor` verb, followed by the interface's name
```
rns monitor eth0
```
- activity is displayed in bytes by default, but using `-b` or `--bit` flag, activity gets displayed in bits
```
rns monitor eth0 -b
```

### Setting
- to set an interface's status (such as `up` or `down`), use `set` verb
  - this operation requires root privilegies, and in some cases running with `sudo` might not be enough
```
rns set interface eth0 status up
```

### Help 
- run `rns help` to get help

### Version
- version can be checked running `rns version` or `rns v`