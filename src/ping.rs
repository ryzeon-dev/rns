use icmp;
use std::net::{IpAddr};
use std::time::Duration;

pub fn ping(target: [u8; 4], timeout: Duration, count: usize) -> bool {
    let mut sock = match icmp::IcmpSocket::connect(IpAddr::from(target)) {
        Err(why) => {
            println!("{:?}", why);
            return false;
        },
        Ok(socket) => {
            socket
        }
    };
    sock.set_write_timeout(Some(timeout));

    let payload: &[u8] = &[0, 0, 0, 0];
    let mut responsive = false;

    for _ in 0..count {
        let res = sock.send(payload);
        println!("{:?}", res);

        match res {
            Ok(_) => { responsive = true; },
            Err(_) => {}
        }
    }

    return responsive;
}