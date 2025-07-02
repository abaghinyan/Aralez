// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub fn run(full_path: &Path) {
    let mut file = match fs::File::create(full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Could not write to {}: {}", full_path.display(), e);
            return;
        }
    };

    writeln!(file, "[Linux System Information]\n").unwrap();

    // OS & kernel
    if let Ok(osr) = fs::read_to_string("/etc/os-release") {
        for line in osr.lines().filter(|l| l.contains("NAME") || l.contains("VERSION")) {
            writeln!(file, "{}", line).unwrap();
        }
    }
    if let Ok(uname) = Command::new("uname").arg("-r").output() {
        writeln!(file, "Kernel Version: {}", String::from_utf8_lossy(&uname.stdout).trim()).unwrap();
    }

    // Hostname
    if let Ok(h) = fs::read_to_string("/etc/hostname") {
        writeln!(file, "Hostname: {}", h.trim()).unwrap();
    }

    // Uptime
    if let Ok(uptime) = fs::read_to_string("/proc/uptime") {
        let secs: f64 = uptime.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0.0);
        writeln!(file, "Uptime: {:.2} seconds", secs).unwrap();
    }

    // Logged-in users
    if let Ok(users) = Command::new("who").output() {
        writeln!(file, "\nLogged-in Users:") .unwrap();
        writeln!(file, "{}", String::from_utf8_lossy(&users.stdout)) .unwrap();
    }

    // CPU Info
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        let model = cpuinfo.lines().find(|l| l.starts_with("model name"));
        let cores = cpuinfo.lines().filter(|l| l.starts_with("processor")).count();
        if let Some(model) = model {
            writeln!(file, "CPU: {}", model.split(':').nth(1).unwrap_or("").trim()).unwrap();
        }
        writeln!(file, "Cores: {}", cores).unwrap();
    }

    // Memory
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines().take(5) {
            writeln!(file, "{}", line).unwrap();
        }
    }

    // Disk space
    if let Ok(df) = Command::new("df").arg("-h").output() {
        writeln!(file, "\nDisk Usage:").unwrap();
        writeln!(file, "{}", String::from_utf8_lossy(&df.stdout)).unwrap();
    }

    // Network interfaces
    if let Ok(ip) = Command::new("ip").arg("a").output() {
        writeln!(file, "\nNetwork Interfaces:").unwrap();
        writeln!(file, "{}", String::from_utf8_lossy(&ip.stdout)).unwrap();
    }

    dprintln!("[INFO] Linux systeminfo written to {}", full_path.display());
}
