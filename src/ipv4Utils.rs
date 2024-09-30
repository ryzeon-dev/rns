pub fn hexByteToU8(hexa: &str) -> usize {
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

pub fn makeu8Vec(ip: String) -> Vec<u8> {
    let splitted = ip.split(".");
    let mut uIP = Vec::<u8>::new();

    for octet in splitted {
        uIP.push(octet.parse::<u8>().unwrap())
    }

    return uIP
}

pub fn makeBaseIP(ip: &Vec<u8>, mask: &Vec<u8>) -> Vec<u8> {
    let mut baseIP = Vec::<u8>::new();

    for i in 0..4 {
        baseIP.push(ip[i] & mask[i]);
    }

    return baseIP
}

pub fn makeEndIP(ip: &Vec<u8>, inverseMask: &Vec<u8>) -> Vec<u8> {
    let mut endIP = Vec::<u8>::new();

    for i in 0..4 {
        endIP.push(ip[i] | inverseMask[i]);
    }

    return endIP
}

pub fn makeInverseMask(mask: &Vec<u8>) -> Vec<u8> {
    let mut inverse = Vec::<u8>::new();

    for i in 0..4 {
        inverse.push(255 - mask[i]);
    }

    return inverse
}

pub fn increment(ip: &Vec<u8>) -> Vec<u8> {
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

pub fn ipToString(ip: &Vec<u8>) -> String {
    let mut res = Vec::<String>::new();

    for octet in ip {
        res.push(format!("{}", octet));
    }

    res.join(".").to_string()
}

pub fn maskFromCidr(cidr: u8) -> Vec<u8> {
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

pub fn decodeAddress(address: String) -> String {
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