// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use std::io::Write;
use std::io::BufRead;

#[derive(Debug)]
struct MemoryMapping {
    pid: u32,
    exe_path: String,
    maps: Vec<String>,
}

#[derive(Debug)]
struct LoadedModule {
    name: String,
    size: usize,
    address: String,
}

pub fn run(full_path: &Path) {
    let mut output = match File::create(full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Cannot create output: {}", e);
            return;
        }
    };

    writeln!(&mut output, "[Live Memory Forensics Report]\n").unwrap();
    writeln!(&mut output, "[+] Hidden Processes:").unwrap();
    match detect_hidden_processes() {
        Ok(pids) => {
            for pid in pids {
                writeln!(&mut output, " - PID {} appears to be hidden", pid).unwrap();
            }
        }
        Err(e) => writeln!(&mut output, "[!] Error: {}", e).unwrap(),
    }

    writeln!(&mut output, "\n[+] Loaded Kernel Modules:").unwrap();
    match list_loaded_modules() {
        Ok(mods) => {
            for m in mods {
                writeln!(
                    &mut output,
                    " - {} at {} ({} bytes)",
                    m.name, m.address, m.size
                )
                .unwrap();
            }
        }
        Err(e) => writeln!(&mut output, "[!] Error: {}", e).unwrap(),
    }

    writeln!(&mut output, "\n[+] Suspicious Memory Mappings:").unwrap();
    match scan_suspicious_mmaps() {
        Ok(maps) => {
            for map in maps {
                writeln!(
                    &mut output,
                    " - PID {} [{}]: {} entries",
                    map.pid,
                    map.exe_path,
                    map.maps.len()
                )
                .unwrap();
                for entry in &map.maps {
                    writeln!(&mut output, "   -> {}", entry).unwrap();
                }
            }
        }
        Err(e) => writeln!(&mut output, "[!] Error: {}", e).unwrap(),
    }

    dprintln!("[INFO] Memory analysis written to: {}", full_path.display());
}

fn detect_hidden_processes() -> Result<Vec<u32>, Box<dyn std::error::Error>> {
    let ps_output = Command::new("ps").arg("-e").output()?;
    let listed_pids: Vec<u32> = String::from_utf8_lossy(&ps_output.stdout)
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect();

    let mut actual_pids = vec![];
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
            if !listed_pids.contains(&pid) {
                actual_pids.push(pid);
            }
        }
    }
    Ok(actual_pids)
}

fn list_loaded_modules() -> Result<Vec<LoadedModule>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string("/proc/modules")?;
    let mut modules = vec![];

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            modules.push(LoadedModule {
                name: parts[0].to_string(),
                size: parts[1].parse().unwrap_or(0),
                address: parts[5].to_string(),
            });
        }
    }
    Ok(modules)
}

fn scan_suspicious_mmaps() -> Result<Vec<MemoryMapping>, Box<dyn std::error::Error>> {
    let mut results = vec![];
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let pid_str = entry.file_name().to_string_lossy().to_string();
        if let Ok(pid) = pid_str.parse::<u32>() {
            let exe_path = fs::read_link(entry.path().join("exe")).unwrap_or_default();
            let maps_path = entry.path().join("maps");
            if let Ok(file) = File::open(maps_path) {
                let reader = BufReader::new(file);
                let suspicious: Vec<String> = reader
                    .lines()
                    .flatten()
                    .filter(|line| line.contains("[stack]") || line.contains("[heap]") || line.contains("rw-p"))
                    .collect();

                if !suspicious.is_empty() {
                    results.push(MemoryMapping {
                        pid,
                        exe_path: exe_path.display().to_string(),
                        maps: suspicious,
                    });
                }
            }
        }
    }
    Ok(results)
}
