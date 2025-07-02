//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs::{self, File, read_link};
use std::io::{self, Write, BufReader};
use std::path::{Path, PathBuf};
use md5;

pub fn run(full_path: &Path) {
    let mut file = match File::create(&full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Failed to create file at `{}`: {}", full_path.display(), e);
            return;
        }
    };

    let processes = match get_processes() {
        Ok(p) => p,
        Err(e) => {
            dprintln!("[ERROR] Failed to retrieve processes: {}", e);
            return;
        }
    };

    // Write CSV header
    if let Err(e) = writeln!(
        file,
        "pid,ppid,name,state,cmdline,exe,md5,cwd,root,uid,euid,suid,gid,egid,sgid,pgrp,threads,start_time,nice,resident_size,total_size,disk_bytes_read,disk_bytes_written,user_time,system_time"
    ) {
        dprintln!("[ERROR] Failed to write CSV header: {}", e);
        return;
    }

    for process in processes {
        if let Err(e) = write_process_csv_row(&mut file, &process) {
            dprintln!(
                "[ERROR] Failed to write process info to file `{}`: {}",
                full_path.display(),
                e
            );
            return;
        }
    }

    dprintln!("[INFO] Process CSV has been written to: {}", full_path.display());
}

#[derive(Debug)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    cmdline: String,
    exe: PathBuf,
    cwd: Option<PathBuf>,
    root: Option<PathBuf>,
    md5: Option<String>,
    uid: Option<u32>,
    euid: Option<u32>,
    suid: Option<u32>,
    gid: Option<u32>,
    egid: Option<u32>,
    sgid: Option<u32>,
    state: String,
    start_time: Option<u64>,
    nice: Option<i32>,
    pgroup: Option<u32>,
    threads: Option<u32>,
    resident_size: Option<u64>,
    total_size: Option<u64>,
    disk_bytes_read: Option<u64>,
    disk_bytes_written: Option<u64>,
    user_time: Option<u64>,
    system_time: Option<u64>,
}

fn get_processes() -> Result<Vec<ProcessInfo>, Box<dyn std::error::Error>> {
    let mut processes = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy().into_owned();
        if let Ok(pid) = pid_str.parse::<u32>() {
            let proc_path = entry.path();
            let mut process = ProcessInfo {
                pid,
                ppid: 0,
                name: String::new(),
                cmdline: String::new(),
                exe: PathBuf::new(),
                cwd: None,
                root: None,
                md5: None,
                uid: None,
                euid: None,
                suid: None,
                gid: None,
                egid: None,
                sgid: None,
                state: String::new(),
                start_time: None,
                nice: None,
                pgroup: None,
                threads: None,
                resident_size: None,
                total_size: None,
                disk_bytes_read: None,
                disk_bytes_written: None,
                user_time: None,
                system_time: None,
            };

            // Parse stat
            if let Ok(stat) = fs::read_to_string(proc_path.join("stat")) {
                let parts: Vec<&str> = stat.split_whitespace().collect();
                process.state = parts.get(2).unwrap_or(&"?").to_string();
                process.ppid = parts.get(3).and_then(|v| v.parse().ok()).unwrap_or(0);
                process.pgroup = parts.get(4).and_then(|v| v.parse().ok());
                process.user_time = parts.get(13).and_then(|v| v.parse().ok());
                process.system_time = parts.get(14).and_then(|v| v.parse().ok());
                process.nice = parts.get(18).and_then(|v| v.parse().ok());
                process.start_time = parts.get(21).and_then(|v| v.parse().ok());
            }

            // cmdline
            if let Ok(c) = fs::read_to_string(proc_path.join("cmdline")) {
                process.cmdline = c.replace('\0', " ");
            }

            // name
            if let Ok(n) = fs::read_to_string(proc_path.join("comm")) {
                process.name = n.trim().to_string();
            }

            // uid/gid/threads
            if let Ok(status) = fs::read_to_string(proc_path.join("status")) {
                for line in status.lines() {
                    if line.starts_with("Uid:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        process.uid = parts.get(1).and_then(|v| v.parse().ok());
                        process.euid = parts.get(2).and_then(|v| v.parse().ok());
                        process.suid = parts.get(3).and_then(|v| v.parse().ok());
                    } else if line.starts_with("Gid:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        process.gid = parts.get(1).and_then(|v| v.parse().ok());
                        process.egid = parts.get(2).and_then(|v| v.parse().ok());
                        process.sgid = parts.get(3).and_then(|v| v.parse().ok());
                    } else if line.starts_with("Threads:") {
                        process.threads = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                    }
                }
            }

            // io
            if let Ok(io_data) = fs::read_to_string(proc_path.join("io")) {
                for line in io_data.lines() {
                    if line.starts_with("read_bytes:") {
                        process.disk_bytes_read = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                    } else if line.starts_with("write_bytes:") {
                        process.disk_bytes_written = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                    }
                }
            }

            // exe/cwd/root and hash
            process.cwd = read_link(proc_path.join("cwd")).ok();
            process.root = read_link(proc_path.join("root")).ok();
            if let Ok(exe_path) = read_link(proc_path.join("exe")) {
                process.exe = exe_path.clone();
                if let Ok(file) = File::open(&exe_path) {
                    let mut buf = Vec::new();
                    let mut reader = BufReader::new(file);
                    std::io::copy(&mut reader, &mut buf)?;
                    let hash = md5::compute(&buf);
                    process.md5 = Some(format!("{:x}", hash));
                }
            }

            processes.push(process);
        }
    }

    Ok(processes)
}

fn write_process_csv_row<W: Write>(writer: &mut W, p: &ProcessInfo) -> io::Result<()> {
    writeln!(
        writer,
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        p.pid,
        p.ppid,
        escape_csv(&p.name),
        p.state,
        escape_csv(&p.cmdline),
        escape_csv(&p.exe.display().to_string()),
        p.md5.as_deref().unwrap_or(""),
        p.cwd.as_ref().map(|c| c.display().to_string()).unwrap_or_default(),
        p.root.as_ref().map(|r| r.display().to_string()).unwrap_or_default(),
        opt_u32(p.uid),
        opt_u32(p.euid),
        opt_u32(p.suid),
        opt_u32(p.gid),
        opt_u32(p.egid),
        opt_u32(p.sgid),
        opt_u32(p.pgroup),
        opt_u32(p.threads),
        opt_u64(p.start_time),
        opt_i32(p.nice),
        opt_u64(p.resident_size),
        opt_u64(p.total_size),
        opt_u64(p.disk_bytes_read),
        opt_u64(p.disk_bytes_written),
        opt_u64(p.user_time),
        opt_u64(p.system_time)
    )
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn opt_u32(v: Option<u32>) -> String {
    v.map_or("".to_string(), |n| n.to_string())
}

fn opt_u64(v: Option<u64>) -> String {
    v.map_or("".to_string(), |n| n.to_string())
}

fn opt_i32(v: Option<i32>) -> String {
    v.map_or("".to_string(), |n| n.to_string())
}
