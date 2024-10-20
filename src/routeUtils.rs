use std::fs;
use crate::utils::removeBlanks;
use crate::ipv4Utils::decodeAddress;

pub fn getRoutes() -> Vec<(String, String, String, String, String)> {
    let mut res = Vec::<(String, String, String, String, String)>::new();

    let routeFile = fs::read_to_string("/proc/net/route");
    let routesFileContent = match routeFile {
        Err(_) => {
            eprintln!("Impossible to read routes data from procfs");
            std::process::exit(1);
        },

        Ok(content) => {
            content
        }
    };

    for line in routesFileContent.split("\n") {
        if line.contains("Iface") || line.is_empty() {
            continue
        }

        let splittedLine = removeBlanks(&mut line.to_string().split("\t").collect::<Vec<&str>>());

        let iface = splittedLine.get(0).unwrap().to_owned();
        let destinationHex = splittedLine.get(1).unwrap().to_owned();
        let destination = decodeAddress(destinationHex);

        let gatewayHex = splittedLine.get(2).unwrap().to_owned();
        let gateway = decodeAddress(gatewayHex);

        let metric = splittedLine.get(6).unwrap().to_owned();
        let maskHex = splittedLine.get(7).unwrap().to_owned();
        let mask = decodeAddress(maskHex);

        res.push((iface, destination, gateway, metric, mask));
    }

    return res;
}