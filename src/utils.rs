use std::collections::HashMap;
use std::fs;
use crate::ipv4Utils::decodeAddress;

pub fn decodePort(port: String) -> String {
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

pub fn removeBlanks(list: &mut Vec<&str>) -> Vec<String> {
    let mut new = Vec::<String>::new();

    for element in list {
        if !element.is_empty() {
            new.push(element.to_string());
        }
    }

    new
}

pub fn unpackLine(line: String) -> (String, String, String) {
    let splitted = removeBlanks(&mut line.split(" ").collect::<Vec<&str>>());

    let localPair = splitted.get(1).unwrap().split(":").collect::<Vec<&str>>();
    let listenAddress = decodeAddress((&localPair[0]).to_string());

    let listenPort = format!("{}", decodePort((&localPair[1]).to_string()));
    let inode = splitted.get(9).unwrap().trim().to_string();

    (listenAddress, listenPort, inode)
}

pub fn parseFile(filePath: String, tcp: bool) -> HashMap<String, (String, String)> {
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
