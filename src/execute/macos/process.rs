//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

/// Enumerate all running processes using the Darwin `libproc` API
/// (`proc_listallpids`, `proc_pidinfo`, `proc_pidpath`) and write
/// a rich CSV with per-process memory, threads, CPU time, exe path,
/// and MD5 hash of each executable.  None of this is obtainable
/// from a single macOS command in structured form.
pub fn run(full_path: &Path) {
    let mut file = match File::create(full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Could not write to {}: {}", full_path.display(), e);
            return;
        }
    };

    // CSV header — mirrors the Linux ProcInfo schema
    if let Err(e) = writeln!(
        file,
        "pid,ppid,name,uid,gid,nice,threads,virtual_size,resident_size,\
         user_time_us,system_time_us,faults,pageins,cow_faults,\
         mach_syscalls,unix_syscalls,context_switches,exe_path,md5"
    ) {
        dprintln!("[ERROR] Failed to write header: {}", e);
        return;
    }

    unsafe {
        // Step 1: get the number of pids
        let count = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 {
            dprintln!("[WARN] proc_listallpids returned {}", count);
            return;
        }

        // Allocate buffer with headroom
        let capacity = (count as usize) * 2;
        let mut pids: Vec<libc::pid_t> = vec![0; capacity];
        let actual = libc::proc_listallpids(
            pids.as_mut_ptr() as *mut libc::c_void,
            (capacity * std::mem::size_of::<libc::pid_t>()) as libc::c_int,
        );
        if actual <= 0 {
            dprintln!("[WARN] proc_listallpids (second call) returned {}", actual);
            return;
        }

        let pid_count = actual as usize;
        pids.truncate(pid_count);

        for &pid in &pids {
            if pid == 0 { continue; }

            // Step 2: proc_pidinfo → proc_taskallinfo (bsd info + task info)
            let mut info: libc::proc_taskallinfo = std::mem::zeroed();
            let ret = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKALLINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libc::proc_taskallinfo>() as libc::c_int,
            );
            if ret <= 0 { continue; }

            let bsd = &info.pbsd;
            let task = &info.ptinfo;

            // Extract process name from pbi_comm
            let name = cstr_to_string(&bsd.pbi_comm);

            // Step 3: proc_pidpath → full executable path
            let mut pathbuf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            let plen = libc::proc_pidpath(
                pid,
                pathbuf.as_mut_ptr() as *mut libc::c_void,
                libc::PROC_PIDPATHINFO_MAXSIZE as u32,
            );
            let exe_path = if plen > 0 {
                String::from_utf8_lossy(&pathbuf[..plen as usize]).to_string()
            } else {
                String::new()
            };

            // Step 4: MD5 hash of the executable on disk
            let md5_hash = if !exe_path.is_empty() {
                compute_md5(&exe_path).unwrap_or_default()
            } else {
                String::new()
            };

            // Write CSV row
            if let Err(e) = writeln!(
                file,
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                pid,
                bsd.pbi_ppid,
                escape_csv(&name),
                bsd.pbi_uid,
                bsd.pbi_gid,
                bsd.pbi_nice,
                task.pti_threadnum,
                task.pti_virtual_size,
                task.pti_resident_size,
                task.pti_total_user,
                task.pti_total_system,
                task.pti_faults,
                task.pti_pageins,
                task.pti_cow_faults,
                task.pti_syscalls_mach,
                task.pti_syscalls_unix,
                task.pti_csw,
                escape_csv(&exe_path),
                md5_hash,
            ) {
                dprintln!("[ERROR] Failed to write pid {}: {}", pid, e);
                continue;
            }
        }
    }

    dprintln!("[INFO] macOS process info written to {}", full_path.display());
}

/// Convert a fixed-size C char buffer to a Rust String
fn cstr_to_string(buf: &[libc::c_char]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let u8_slice = unsafe { &*((&buf[..end]) as *const [libc::c_char] as *const [u8]) };
    String::from_utf8_lossy(u8_slice).into_owned()
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn compute_md5(path: &str) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut context = md5::Context::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 { break; }
        context.consume(&buffer[..n]);
    }
    Ok(format!("{:x}", context.compute()))
}
