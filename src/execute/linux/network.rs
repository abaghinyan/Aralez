//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub fn run(full_path: &Path) {
    let mut file = match File::create(full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Failed to create file at `{}`: {}", full_path.display(), e);
            return;
        }
    };

    // Write CSV header
    if let Err(e) = writeln!(
        file,
        "protocol,local_address,local_port,remote_address,remote_port,state,uid,inode"
    ) {
        dprintln!("[ERROR] Failed to write header: {}", e);
        return;
    }

    let protocols = ["tcp", "tcp6", "udp", "udp6"];
    for proto in &protocols {
        if let Err(e) = parse_net_file(proto, &mut file) {
            dprintln!("[WARN] Failed to parse {}: {}", proto, e);
        }
    }

    dprintln!("[INFO] Network connections written to: {}", full_path.display());
}

fn parse_net_file<W: Write>(proto: &str, writer: &mut W) -> io::Result<()> {
    let path = format!("/proc/net/{}", proto);
    let file = File::open(&path)?;
    let reader = io::BufReader::new(file);

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if i == 0 {
            continue; // skip header
        }

        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }

        let local_ip_port = parse_ip_port(cols[1], proto.ends_with("6"));
        let remote_ip_port = parse_ip_port(cols[2], proto.ends_with("6"));
        let state = parse_tcp_state(cols[3]);
        let uid = cols[7];
        let inode = cols[9];

        writeln!(
            writer,
            "{},{},{},{},{},{},{},{}",
            proto,
            local_ip_port.0,
            local_ip_port.1,
            remote_ip_port.0,
            remote_ip_port.1,
            state,
            uid,
            inode
        )?;
    }

    Ok(())
}

fn parse_ip_port(raw: &str, is_ipv6: bool) -> (String, u16) {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 2 {
        return ("INVALID".into(), 0);
    }

    let ip_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    let ip = if is_ipv6 {
        if ip_hex.len() == 32 {
            let bytes = (0..16)
                .map(|i| u8::from_str_radix(&ip_hex[2 * i..2 * i + 2], 16).unwrap_or(0))
                .collect::<Vec<u8>>();

            Ipv6Addr::from([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ])
            .to_string()
        } else {
            "INVALID_IPV6".into()
        }
    } else {
        let ip_num = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
        Ipv4Addr::from(ip_num).to_string()
    };

    (ip, port)
}

fn parse_tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}
