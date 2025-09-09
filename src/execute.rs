//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

#[cfg(target_os = "windows")]
#[path = "execute/windows"]
pub mod windows_internal {
    pub mod network;
    pub mod process;
    pub mod process_details;
}

#[cfg(target_os = "linux")]
#[path = "execute/linux"]
pub mod linux_internal {
    pub mod memory;
    pub mod network;
    pub mod package;
    pub mod process;
    pub mod system;
}

use crate::config::ExecType;
use std::fs::{remove_file, File};
use std::io::{self, Write};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use std::{sync::mpsc, thread, time::Duration};

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use libc;

#[cfg(target_os = "windows")]
mod windows_imports {
    pub use super::windows_internal::*;
    pub use crate::resource::extract_resource;
    pub use windows::core::PCWSTR;
    pub use windows::Win32::Foundation::*;
    pub use windows::Win32::System::JobObjects::*;
    pub use windows::Win32::System::Threading::*;
}

// Bring into scope at top-level
#[cfg(target_os = "windows")]
use windows_imports::*;

#[cfg(target_os = "linux")]
mod linux_imports {
    pub use super::linux_internal::*;
}

// Bring into scope at top-level
#[cfg(target_os = "linux")]
use linux_imports::*;

#[cfg(target_os = "windows")]
pub fn run_internal(tool_name: &str, output_filename: &str) -> Option<String> {
    let start_time = Instant::now();
    dprintln!("[INFO] > {} | Starting execution", tool_name);

    let output_file_path = Path::new(output_filename);
    let output: Option<String> = None;

    match tool_name {
        "ProcInfo" => {
            process::run(&output_file_path);
        }
        "ProcDetailsInfo" => process_details::run(&output_file_path),
        "PortsInfo" => {
            network::run(&output_file_path);
        }
        &_ => {
            dprintln!("[ERROR] > {} | Internal tool not found", tool_name);
            return None;
        }
    }
    dprintln!(
        "[INFO] > {} | The output has been saved to: {}",
        tool_name,
        output_filename
    );
    let elapsed = start_time.elapsed();
    dprintln!(
        "[INFO] > {} | Execution completed in {:?}.{:?} sec",
        tool_name, 
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );

    output
}

#[cfg(target_os = "linux")]
pub fn run_internal(tool_name: &str, output_filename: &str) -> Option<String> {
    let start_time = Instant::now();
    dprintln!("[INFO] > {} | Starting execution", tool_name);

    let output_file_path = Path::new(output_filename);
    let output: Option<String> = None;

    match tool_name {
        "ProcInfo" => process::run(&output_file_path),
        "Network" => network::run(&output_file_path),
        "Memory" => memory::run(&output_file_path),
        "SystemInfo" => system::run(&output_file_path),
        "PackageManager" => package::run(&output_file_path),
        &_ => {
            dprintln!("[ERROR] > {} | Internal tool not found", tool_name);
            return None;
        }
    }
    dprintln!(
        "[INFO] > {} | The output has been saved to: {}",
        tool_name,
        output_filename
    );
    let elapsed = start_time.elapsed();
    dprintln!(
        "[INFO] > {} | Execution completed in {:?}.{:?} sec",
        tool_name, 
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );

    output
}

#[cfg_attr(unix, allow(unused_variables))]
pub fn run(
    mut name: String,
    args: &[&str],
    exec_type: ExecType,
    exe_bytes: Option<&[u8]>,
    output_path: Option<&str>,
    output_file: &str,
    memory_limit: Option<usize>, // MB on input
    timeout: Option<u64>,
    // STRICT cap in BYTES (not MB!)
    max_size_bytes: Option<u64>,
) -> Option<String> {
    let task_start_time = Instant::now();
    let mut display_name = name.clone();

    // Prepare external executable (write bytes to temp path)
    if exec_type == ExecType::External {
        let buffer = match exe_bytes {
            Some(bytes) => bytes,
            None => {
                dprintln!("[ERROR] > {} | Content of the external file not found", name);
                return None;
            }
        };
        let path = match output_path {
            Some(p) => p,
            None => {
                dprintln!("[ERROR] > {} | The output path for the executable not found", name);
                return None;
            }
        };
        let temp_exe_path = match save_to_temp_file(&name, buffer, path) {
            Ok(path) => path,
            Err(e) => {
                dprintln!("[ERROR] > {} | Failed to save to temp file: {}", name, e);
                return None;
            }
        };

        name = temp_exe_path.to_string_lossy().to_string();
        display_name = temp_exe_path
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .unwrap_or(name.as_str())
            .to_string();
    }

    // ===== Spawn child (with process-group / job object isolation) =====

    #[cfg(unix)]
    let mut cmd = Command::new(&name);

    #[cfg(unix)]
    let spawn_res = unsafe {
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null()) // don't block on stderr
            .pre_exec(|| {
                // Put child into its own process group (pgid = pid)
                libc::setpgid(0, 0);
                Ok(())
            })
            .spawn()
    };

    #[cfg(not(unix))]
    let spawn_res = Command::new(&name)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // don't block on stderr
        .spawn();

    let mut child = match spawn_res {
        Ok(child) => {
            dprintln!(
                "[INFO] > {} ({}) | Starting execution with args: {:?}",
                display_name,
                child.id(),
                args
            );
            child
        }
        Err(e) => {
            dprintln!("[ERROR] > {} | Failed to spawn process: {}", display_name, e);
            return None;
        }
    };

    let pid = child.id();

    // Windows: create & assign Job Object if we might need to kill process tree
    #[cfg(target_family = "windows")]
    let mut job_handle: Option<HANDLE> = None;

    #[cfg(target_family = "windows")]
    {
        let need_job = timeout.is_some() || max_size_bytes.unwrap_or(0) > 0 || memory_limit.is_some();
        if need_job {
            let mem_bytes = memory_limit.map(|m| m * 1024 * 1024);
            if let Some(job) = create_job_object(mem_bytes, /*kill_on_close*/ true) {
                assign_to_job(job, &child);
                job_handle = Some(job);
                dprintln!(
                    "[INFO] > {} ({}) | Assigned to Job Object{}",
                    display_name,
                    pid,
                    if let Some(m) = mem_bytes {
                        format!(" (mem limit {} MB, kill-on-close)", m / 1024 / 1024)
                    } else {
                        " (kill-on-close)".to_string()
                    }
                );
            }
        }

        // If memory_limit was provided but we didn't put the process in a job above, keep the legacy path:
        if job_handle.is_none() {
            if let Some(_mem_l) = memory_limit {
                let memory_limit_value = _mem_l * 1024 * 1024;
                if let Some(job) = create_memory_limited_job(memory_limit_value) {
                    assign_to_job(job, &child);
                    dprintln!(
                        "[INFO] > {} ({}) | Assigned to memory-limited Job Object ({} MB)",
                        display_name,
                        pid,
                        memory_limit_value / 1024 / 1024
                    );
                    job_handle = Some(job);
                }
            }
        }
    }

    // Take stdout for streaming
    let mut stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            dprintln!("[ERROR] > {} ({}) | Failed to take stdout", display_name, pid);
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };

    // Timeout notifier
    let (to_tx, to_rx) = mpsc::channel::<()>();
    if let Some(timeout_secs) = timeout {
        dprintln!(
            "[INFO] > {} ({}) | Assigned timeout ({} sec)",
            display_name, pid, timeout_secs
        );
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(timeout_secs));
            let _ = to_tx.send(());
        });
    }

    // Open destination file
    let mut out_file = match File::create(Path::new(output_file)) {
        Ok(f) => f,
        Err(e) => {
            dprintln!(
                "[ERROR] > {} ({}) | Failed to create output file: {}",
                display_name, pid, e
            );
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };

    // Stream stdout -> file with a STRICT cap
    let mut reader = BufReader::new(&mut stdout);
    let mut buf = [0u8; 8192];
    let mut total_written: u64 = 0;
    let mut killed = false;
    let mut mirrored: Vec<u8> = Vec::new();

    // Treat 0 as "no cap" (keep your previous behavior)
    let max_bytes = max_size_bytes.and_then(|b| if b == 0 { None } else { Some(b) });

    #[cfg(unix)]
    let pgid: libc::pid_t = unsafe {
        // getpgid returns -1 on error (with errno set). Fall back to child's pid.
        let r = libc::getpgid(child.id() as libc::pid_t);
        if r < 0 { child.id() as libc::pid_t } else { r }
    };

    let mut kill_child = |reason: &str| {
        if !killed {
            dprintln!("[WARN] > {} ({}) | {}", display_name, pid, reason);

            #[cfg(unix)]
            unsafe {
                // Negative PGID => kill entire process group
                libc::kill(-pgid, libc::SIGKILL);
            }

            #[cfg(target_family = "windows")]
            unsafe {
                if let Some(job) = job_handle {
                    let _ = TerminateJobObject(job, 1);
                } else {
                    let _ = child.kill();
                }
            }

            #[cfg(all(not(unix), not(target_family = "windows")))]
            {
                let _ = child.kill();
            }

            let _ = child.wait();
            killed = true;
        }
    };

    loop {
        // Check timeout
        if to_rx.try_recv().is_ok() {
            kill_child("Execution timed out");
            break;
        }

        match reader.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                // How many bytes are still allowed?
                let n_to_write = if let Some(limit) = max_bytes {
                    let remaining = limit.saturating_sub(total_written);
                    remaining.min(n as u64) as usize
                } else {
                    n
                };

                // Write only the allowed slice
                if n_to_write > 0 {
                    if let Err(e) = out_file.write_all(&buf[..n_to_write]) {
                        dprintln!(
                            "[ERROR] > {} ({}) | Failed writing to output file: {}",
                            display_name, pid, e
                        );
                        kill_child("Stopping due to write error");
                        break;
                    }
                    total_written += n_to_write as u64;
                    mirrored.extend_from_slice(&buf[..n_to_write]);
                }

                // If we hit the limit exactly, stop right now
                if let Some(limit) = max_bytes {
                    if total_written >= limit {
                        kill_child("Max output size reached");
                        break;
                    }
                }
            }
            Err(e) => {
                dprintln!(
                    "[ERROR] > {} ({}) | Read error from stdout: {}",
                    display_name, pid, e
                );
                kill_child("Stopping due to read error");
                break;
            }
        }
    }

    // Ensure the process is reaped
    match child.try_wait() {
        Ok(Some(_)) => { /* already exited */ }
        _ => {
            let _ = child.wait(); // block until it exits
        }
    }
    // Flush file
    if let Err(e) = out_file.flush() {
        dprintln!(
            "[ERROR] > {} ({}) | Failed to flush output file: {}",
            display_name, pid, e
        );
    }

    // Remove temp exe if we created it
    if exec_type == ExecType::External {
        if let Err(e) = cleanup_temp_file(&name) {
            dprintln!(
                "[ERROR] > {} ({}) | Failed to clean up temp file: {}",
                display_name,
                pid,
                e
            );
        }
    }

    dprintln!(
        "[INFO] > {} ({}) | The output has been saved to: {} ({} bytes written{})",
        display_name,
        pid,
        output_file,
        total_written,
        if let Some(limit) = max_bytes { format!(", cap={} bytes", limit) } else { "".to_string() }
    );

    let task_elapsed = task_start_time.elapsed();
    dprintln!(
        "[INFO] > {} ({}) | Execution completed in {:?}.{:?} sec",
        display_name,
        pid,
        task_elapsed.as_secs(),
        task_elapsed.subsec_millis()
    );

    Some(String::from_utf8_lossy(&mirrored).to_string())
}

#[cfg(target_os = "windows")]
pub fn get_list_tools() -> Vec<&'static str> {
    vec![
        "autorunsc.exe",
        "handle.exe",
        "tcpvcon.exe",
        "pslist.exe",
        "Listdlls.exe",
        "PsService.exe",
        "pipelist.exe",
        "winpmem_mini_rc2.exe",
    ]
}

#[cfg(target_os = "windows")]
pub fn get_bin(name: String) -> Result<Vec<u8>, anyhow::Error> {
    let exe_bytes: Vec<u8> = match name.as_str() {
        "autorunsc.exe" => include_bytes!("../tools/autorunsc.exe").to_vec(),
        "handle.exe" => include_bytes!("../tools/handle.exe").to_vec(),
        "tcpvcon.exe" => include_bytes!("../tools/tcpvcon.exe").to_vec(),
        "pslist.exe" => include_bytes!("../tools/pslist.exe").to_vec(),
        "Listdlls.exe" => include_bytes!("../tools/Listdlls.exe").to_vec(),
        "PsService.exe" => include_bytes!("../tools/PsService.exe").to_vec(),
        "pipelist.exe" => include_bytes!("../tools/pipelist.exe").to_vec(),
        "winpmem_mini_rc2.exe" => include_bytes!("../tools/winpmem_mini_rc2.exe").to_vec(),
        _ => match extract_resource(&name) {
            Ok(bytes) => bytes,
            Err(_) => return Err(anyhow::anyhow!(format!("[ERROR] {} not found", name))),
        },
    };

    Ok(exe_bytes)
}

fn save_to_temp_file(
    _filename: &String,
    exe_bytes: &[u8],
    output_path: &str,
) -> io::Result<PathBuf> {
    let output_file_path = Path::new(output_path).join(_filename);
    let mut file = File::create(&output_file_path)?;
    file.write_all(exe_bytes)?;
    Ok(output_file_path)
}

fn cleanup_temp_file(temp_exe_path: &str) -> io::Result<()> {
    dprintln!("[INFO] > {:?} : Remove the temporary file", temp_exe_path);
    let exec_path = Path::new(temp_exe_path);
    if exec_path.exists() {
        remove_file(exec_path)?;
    }
    Ok(())
}

#[cfg(target_family = "windows")]
fn create_memory_limited_job(limit_bytes: usize) -> Option<HANDLE> {
    unsafe {
        match CreateJobObjectW(None, PCWSTR::null()) {
            Ok(job) => {
                if job.is_invalid() {
                    eprintln!("[ERROR] Job handle is invalid");
                    return None;
                }

                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                info.ProcessMemoryLimit = limit_bytes;

                let result = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &mut info as *mut _ as *mut _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );

                if result.is_ok() {
                    Some(job)
                } else {
                    eprintln!("[ERROR] Failed to set Job Object limit");
                    None
                }
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to create Job Object: {}", e);
                None
            }
        }
    }
}

#[cfg(target_family = "windows")]
fn create_job_object(process_memory_limit: Option<usize>, kill_on_close: bool) -> Option<HANDLE> {
    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null()).ok()?;
        if job.is_invalid() {
            eprintln!("[ERROR] Job handle is invalid");
            return None;
        }

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();

        // IMPORTANT: flags must be JOB_OBJECT_LIMIT, not an integer.
        let mut flags = JOB_OBJECT_LIMIT::default(); // or JOB_OBJECT_LIMIT(0)

        if kill_on_close {
            flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        if let Some(limit) = process_memory_limit {
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.ProcessMemoryLimit = limit;
        }

        info.BasicLimitInformation.LimitFlags = flags;

        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut _,
            core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .is_err()
        {
            eprintln!("[ERROR] Failed to set Job Object limit");
            return None;
        }

        Some(job)
    }
}

#[cfg(target_family = "windows")]
fn assign_to_job(job: HANDLE, child: &std::process::Child) {
    unsafe {
        if let Ok(proc_handle) =
            OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, child.id())
        {
            if !AssignProcessToJobObject(job, proc_handle).is_ok() {
                eprintln!("[ERROR] Failed to assign process to Job Object");
            }
        } else {
            eprintln!("[ERROR] Failed to open process for Job Object assignment");
        }
    }
}
