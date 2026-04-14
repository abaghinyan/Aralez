//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Deep process inspection using `proc_pidinfo(PROC_PIDLISTFDS)`.
///
/// For every running process, enumerates its open file descriptors via
/// the native `libproc` API and reports the FD number and type.
/// Socket FDs (type 2) are especially valuable for forensic network
/// correlation.  No macOS command outputs per-process FD listings
/// in a structured format — `lsof` does it textually but this is the
/// raw kernel data.
pub fn run(full_path: &Path) {
    let mut file = match File::create(full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Could not write to {}: {}", full_path.display(), e);
            return;
        }
    };

    if let Err(e) = writeln!(file, "pid,process_name,fd,fd_type") {
        dprintln!("[ERROR] Failed to write header: {}", e);
        return;
    }

    unsafe {
        // Get all PIDs
        let count = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 { return; }

        let capacity = (count as usize) * 2;
        let mut pids: Vec<libc::pid_t> = vec![0; capacity];
        let actual = libc::proc_listallpids(
            pids.as_mut_ptr() as *mut libc::c_void,
            (capacity * std::mem::size_of::<libc::pid_t>()) as libc::c_int,
        );
        if actual <= 0 { return; }
        pids.truncate(actual as usize);

        for &pid in &pids {
            if pid == 0 { continue; }

            // Get process name for context
            let mut info: libc::proc_taskallinfo = std::mem::zeroed();
            let ret = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKALLINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libc::proc_taskallinfo>() as libc::c_int,
            );
            let name = if ret > 0 {
                cstr_to_string(&info.pbsd.pbi_comm)
            } else {
                String::new()
            };

            // List all FDs for this process
            // First call: get required buffer size
            let fd_buf_size = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            );
            if fd_buf_size <= 0 { continue; }

            let fd_count = fd_buf_size as usize / std::mem::size_of::<libc::proc_fdinfo>();
            let mut fds: Vec<libc::proc_fdinfo> = vec![std::mem::zeroed(); fd_count];
            let actual_size = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut libc::c_void,
                fd_buf_size,
            );
            if actual_size <= 0 { continue; }

            let actual_fd_count = actual_size as usize / std::mem::size_of::<libc::proc_fdinfo>();

            for i in 0..actual_fd_count {
                let fd = &fds[i];
                let fd_type_str = match fd.proc_fdtype as i32 {
                    libc::PROX_FDTYPE_VNODE    => "vnode",
                    libc::PROX_FDTYPE_SOCKET   => "socket",
                    libc::PROX_FDTYPE_PSHM     => "pshm",
                    libc::PROX_FDTYPE_PSEM     => "psem",
                    libc::PROX_FDTYPE_KQUEUE   => "kqueue",
                    libc::PROX_FDTYPE_PIPE     => "pipe",
                    libc::PROX_FDTYPE_FSEVENTS => "fsevents",
                    _                          => "unknown",
                };

                let _ = writeln!(
                    file,
                    "{},{},{},{}",
                    pid,
                    escape_csv(&name),
                    fd.proc_fd,
                    fd_type_str,
                );
            }
        }
    }

    dprintln!("[INFO] macOS process details written to {}", full_path.display());
}

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
