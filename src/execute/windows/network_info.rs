//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use windows::Win32::Networking::WinSock::ntohs;
use windows::Win32::NetworkManagement::IpHelper::{GetTcpTable, MIB_TCPTABLE};
use windows::Win32::Foundation::*;

fn parse_ip(addr: u32) -> Ipv4Addr {
    let octets = addr.to_be_bytes();
    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
}

fn parse_tcp_state(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

pub fn get_tcp_connections() -> Vec<(Ipv4Addr, u16, Ipv4Addr, u16, &'static str)> {
    let mut tcp_connections = Vec::new();

    unsafe {
        let mut buffer_size: u32 = 0;
        let result = GetTcpTable(None, &mut buffer_size, false);

        if result != ERROR_INSUFFICIENT_BUFFER.0 {
            dprintln!("[ERROR] Failed to get the required buffer size for TCP table. Error code: {}", result);
            return tcp_connections;
        }

        let mut tcp_table: Vec<u8> = vec![0; buffer_size as usize];
        let result = GetTcpTable(Some(tcp_table.as_mut_ptr() as *mut MIB_TCPTABLE), &mut buffer_size, false);

        if result == NO_ERROR.0 {
            let table = tcp_table.as_ptr() as *const MIB_TCPTABLE;
            let table_ref = &*table;
            for i in 0..table_ref.table.len() as usize {
                let entry = &table_ref.table[i];
                let local_address = parse_ip(entry.dwLocalAddr);
                let local_port = ntohs(entry.dwLocalPort as u16);
                let remote_address = parse_ip(entry.dwRemoteAddr);
                let remote_port = ntohs(entry.dwRemotePort as u16);
                let state = parse_tcp_state(entry.Anonymous.dwState);

                tcp_connections.push((local_address, local_port, remote_address, remote_port, state));
            }
        } else {
            dprintln!("[ERROR] Failed to get TCP table. Error code: {}", result);
        }
    }

    tcp_connections
}

pub fn run_network_info(full_path: &Path) {
    // Get TCP connections
    let tcp_connections = get_tcp_connections();

    // Try to create the file, log error if it fails
    let mut file = match File::create(&full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Failed to create file at `{}`: {}", full_path.display(), e);
            return; // Exit early to avoid proceeding with errors
        }
    };

    // Write the header row, log error if it fails
    if let Err(e) = writeln!(file, "{:<5} {:<22} {:<22} {:<12}", "Proto", "Local Address", "Foreign Address", "State") {
        dprintln!("[ERROR] Failed to write header to file `{}`: {}", full_path.display(), e);
        return; // Exit early if writing the header fails
    }

    // Write the TCP connection information, log errors individually
    for (local_address, local_port, remote_address, remote_port, state) in tcp_connections {
        if let Err(e) = writeln!(
            file,
            "{:<5} {:<22} {:<22} {:<12}",
            "TCP",
            format!("{}:{}", local_address, local_port),
            format!("{}:{}", remote_address, remote_port),
            state
        ) {
            dprintln!(
                "[ERROR] Failed to write connection info to file `{}`: {}",
                full_path.display(),
                e
            );
            return; // Exit early if writing connection info fails
        }
    }

    dprintln!("[INFO] Port information written to {:?}", full_path);
}
