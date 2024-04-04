# rns - Rust Network Scan
- TCP scanning tool written in rust 

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
- give any IP address from the network you want to scan, and the relative netmask

```
rns 192.168.1.25 255.255.255.0
```
- to only check the standard ports add `-std` flag
```
rns 192.168.1.25 255.255.255.0 -std
```
- to check a single address run:
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