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
    pub mod process;
    pub mod network;
    pub mod memory;
    pub mod system;
    pub mod package;
}

use crate::config::ExecType;
use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::fs::{File, remove_file};
use std::path::{Path, PathBuf};

use wait_timeout::ChildExt;
use std::time::Duration;

#[cfg(target_os = "windows")]
mod windows_imports {
    pub use windows::Win32::System::JobObjects::*;
    pub use windows::Win32::System::Threading::*;
    pub use windows::Win32::Foundation::*;
    pub use windows::core::PCWSTR;
    pub use crate::resource::extract_resource;
    pub use super::windows_internal::*;
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
    dprintln!("[INFO] > `{}` | Starting execution", tool_name);

    let output_file_path = Path::new(output_filename);
    let output: Option<String> = None;

    match tool_name {
        "ProcInfo" => {
            process::run(&output_file_path);
        }
        "ProcDetailsInfo" => {
            process_details::run(&output_file_path)
        }
        "PortsInfo" => {
            network::run(&output_file_path);
        }
        &_ => {
            dprintln!("[ERROR] > `{}` | Internal tool not found", tool_name);
            return None;
        }
    }
    dprintln!("[INFO] > `{}` | The output has been saved to: {}", tool_name, output_filename);
    dprintln!("[INFO] > `{}` | Execution completed", tool_name);

    return output;
}

#[cfg(target_os = "linux")] 
pub fn run_internal(tool_name: &str, output_filename: &str) -> Option<String> {
    dprintln!("[INFO] > `{}` | Starting execution", tool_name);

    let output_file_path = Path::new(output_filename);
    let output: Option<String> = None;

    match tool_name {
        "ProcInfo" => {
            process::run(&output_file_path)
        },
        "Network" => {
            network::run(&output_file_path)
        },
        "Memory" => {
            memory::run(&output_file_path)
        },
        "SystemInfo" => {
            system::run(&output_file_path)
        },
        "PackageManager" => {
            package::run(&output_file_path)
        },
        &_ => {
            dprintln!("[ERROR] > `{}` | Internal tool not found", tool_name);
            return None;
        }
    }
    dprintln!("[INFO] > `{}` | The output has been saved to: {}", tool_name, output_filename);
    dprintln!("[INFO] > `{}` | Execution completed", tool_name);

    return output;
}

pub fn run(
    mut name: String,
    args: &[&str],
    exec_type: ExecType,
    exe_bytes: Option<&[u8]>,
    output_path: Option<&str>,
    output_file: &str,
    memory_limit: Option<usize>,
    timeout: Option<u64>
) -> Option<String> {
    let mut display_name = name.clone();
    if exec_type == ExecType::External {
        let buffer = match exe_bytes {
            Some(bytes) => bytes,
            None => {
                dprintln!("[ERROR] > `{}` | Content of the external file not found", name);
                return None;
            }
        };
        let path = match output_path {
            Some(p) => p,
            None => {
                dprintln!("[ERROR] > `{}` | The output path for the executable not found", name);
                return None;
            }
        };
        let temp_exe_path = match save_to_temp_file(&name, buffer, path) {
            Ok(path) => path,
            Err(e) => {
                dprintln!("[ERROR] > `{}` | Failed to save to temp file: {}", name, e);
                return None;
            }
        };

        name = temp_exe_path.to_string_lossy().to_string();
        display_name = temp_exe_path
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .unwrap_or(&name.as_str())
            .to_string();
    }

    let mut child = match Command::new(&name)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            dprintln!(
                "[INFO] > `{}` ({}) | Starting execution with args: {:?}",
                display_name,
                child.id(),
                args
            );
            if let Some(_mem_l) = memory_limit {
                #[cfg(target_family = "windows")]
                {
                    let memory_limit_value = _mem_l * 1024 * 1024; 
                    if let Some(job) = create_memory_limited_job(memory_limit_value) {
                        assign_to_job(job, &child);
                        dprintln!(
                            "[INFO] > `{}` | Assigned to memory-limited Job Object ({} MB)",
                            display_name,
                            memory_limit_value / 1024 / 1024
                        );
                    }
                }
            } 

            child
        }
        Err(e) => {
            dprintln!(
                "[ERROR] > `{}` | Failed to spawn process: {}",
                display_name,
                e
            );
            return None;
        }
    };
    if let Some(timeout_value) = timeout {
        let one_sec = Duration::from_secs(timeout_value);
        let _status_code = match child.wait_timeout(one_sec).unwrap() {
            Some(status) => status.code(),
            None => {
                dprintln!("[WARN] > `{}` | Execution timed out", display_name);
                child.kill().unwrap();
                child.wait().unwrap().code()
            }
        };
    }

    let pid = child.id();

    let output = match child.wait_with_output() {
        Ok(output) => {
            if !output.status.success() {
                let stderr_msg = String::from_utf8_lossy(&output.stderr);
                dprintln!(
                    "[ERROR] > `{}` ({}) | Command failed: {}",
                    display_name,
                    pid,
                    stderr_msg.trim()
                );
            }
            output
        }
        Err(e) => {
            dprintln!(
                "[ERROR] > `{}` ({}) | Failed to execute: {}",
                display_name,
                pid,
                e
            );
            return None;
        }
    };

    dprintln!(
        "[INFO] > `{}` ({}) | Exit code: {:?}",
        display_name,
        pid,
        output.status.code().unwrap_or(-1)
    );

    if let Err(e) = save_output_to_file(&output.stdout, output_file) {
        dprintln!(
            "[ERROR] > `{}` ({}) | Failed to save output to file: {}",
            display_name,
            pid,
            e
        );
    }

    if exec_type == ExecType::External {
        if let Err(e) = cleanup_temp_file(&name) {
            dprintln!(
                "[ERROR] > `{}` ({}) | Failed to clean up temp file: {}",
                display_name,
                pid,
                e
            );
        }
    }

    dprintln!(
        "[INFO] > `{}` ({}) | The output has been saved to: {}",
        display_name,
        pid,
        output_file
    );
    dprintln!("[INFO] > `{}` ({}) | Execution completed", display_name, pid);

    Some(String::from_utf8(output.stdout).unwrap_or_else(|_| "".to_string()))
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

fn save_to_temp_file(_filename: &String, exe_bytes: &[u8], output_path: &str) -> io::Result<PathBuf> {
    let output_file_path = Path::new(output_path).join(_filename);
    let mut file = File::create(&output_file_path)?;
    file.write_all(exe_bytes)?;
    Ok(output_file_path)
}

fn save_output_to_file(output: &[u8], output_filename: &str) -> io::Result<()> {
    let output_file_path = Path::new(output_filename);
    let mut file = File::create(output_file_path)?;
    file.write_all(output)?;
    file.flush()?;
    Ok(())
}

fn cleanup_temp_file(temp_exe_path: &str) -> io::Result<()> {
    dprintln!("[INFO] > `{:?}` : Remove the temporary file", temp_exe_path);
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
fn assign_to_job(job: HANDLE, child: &std::process::Child) {
    unsafe {
        if let Ok(proc_handle) = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, child.id()) {
            if !AssignProcessToJobObject(job, proc_handle).is_ok() {
                eprintln!("[ERROR] Failed to assign process to Job Object");
            }
        } else {
            eprintln!("[ERROR] Failed to open process for Job Object assignment");
        }
    }
}