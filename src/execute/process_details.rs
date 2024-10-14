//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use windows::{
    Win32::System::ProcessStatus::GetProcessMemoryInfo,
    Win32::System::ProcessStatus::{GetProcessImageFileNameW},
    Win32::System::Threading::GetProcessTimes,
    Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, FILETIME},
    Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
        Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, THREADENTRY32, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD,
    },
    Win32::System::Diagnostics::Debug::ReadProcessMemory,
    Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE},
    Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    core::{HRESULT, Result},
};
use windows::Win32::System::ProcessStatus::{PROCESS_MEMORY_COUNTERS};
use std::path::Path;
use sha2::{Sha256, Digest as Sha2Digest}; // Import Digest for SHA256
use std::time::{SystemTime};
use chrono::{DateTime, Utc};
use md5::{Context};

#[derive(Serialize)]
struct ModuleInfo {
    base_name: String,
    path: String,
}

#[derive(Serialize)]
struct ThreadInfo {
    thread_id: u32,
    start_address: usize,
    in_rwx: bool,
    entropy: f64,
    high_entropy: bool,
}

#[derive(Serialize)]
struct ProcessInfo {
    pid: u32,
    name: String,
    parent_pid: u32,
    thread_count: u32,
    priority: i32,
    exe_path: String,
    memory_usage: u64,
    creation_time: String,
    md5_hash: Option<String>,
    sha256_hash: Option<String>,
    modules: Vec<ModuleInfo>,
    threads: Vec<ThreadInfo>,
}


fn get_process_exe_path(pid: u32) -> Option<String> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;
        let mut exe_path = vec![0u16; 260];
        let length = GetProcessImageFileNameW(process_handle, &mut exe_path) as usize;
        let _ = CloseHandle(process_handle);

        if length > 0 {
            Some(String::from_utf16_lossy(&exe_path[..length]))
        } else {
            None
        }
    }
}

fn calculate_md5(path: &str) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut context = Context::new();
    let mut buffer = [0; 1024];

    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 {
            break;
        }
        context.consume(&buffer[..n]);
    }

    Some(format!("{:x}", context.compute()))
}

fn calculate_sha256(path: &str) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    
    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    
    Some(format!("{:x}", hasher.finalize()))
}

fn list_loaded_modules(pid: u32) -> Result<Vec<ModuleInfo>> {
    let mut modules = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
            Ok(handle) => handle,
            Err(e) if e.code() == HRESULT(0x80070005u32 as i32) => {
                dprintln!("[WARN] Access denied for PID: {}. Skipped", pid);
                return Ok(modules); // Return an empty list, or handle as needed
            }
            Err(e) => return Err(e), // Propagate other errors
        };

        let mut me32 = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        if Module32FirstW(snapshot, &mut me32).is_ok() {
            loop {
                let module_name = String::from_utf16_lossy(
                    &me32.szModule[..me32.szModule.iter().position(|&c| c == 0).unwrap_or(me32.szModule.len())],
                );
                let module_path = String::from_utf16_lossy(
                    &me32.szExePath[..me32.szExePath.iter().position(|&c| c == 0).unwrap_or(me32.szExePath.len())],
                );

                modules.push(ModuleInfo {
                    base_name: module_name,
                    path: module_path,
                });

                if Module32NextW(snapshot, &mut me32).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    Ok(modules)
}

fn is_address_in_rwx_section(process_handle: HANDLE, address: usize) -> bool {
    unsafe {
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        if VirtualQueryEx(
            process_handle,
            Some(address as *const _),
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            mem_info.Protect == PAGE_EXECUTE_READWRITE
        } else {
            false
        }
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut frequencies = [0; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let len = data.len() as f64;

    for &count in frequencies.iter() {
        if count > 0 {
            let freq = count as f64 / len;
            entropy -= freq * freq.log2();
        }
    }
    entropy
}

fn scan_memory_for_suspicious_patterns(process_handle: HANDLE, address: usize, size: usize) -> bool {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;

    unsafe {
        if ReadProcessMemory(
            process_handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
        .is_ok()
        {
            let entropy = calculate_entropy(&buffer);
            if entropy > 7.5 {

                return true;
            }
        }
    }
    false
}

fn scan_threads_in_rwx(pid: u32, process_handle: HANDLE) -> Result<Vec<ThreadInfo>> {
    let mut threads = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        let mut te32 = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(snapshot, &mut te32).is_ok() {
            loop {
                if te32.th32OwnerProcessID == pid {
                    let start_address = te32.tpBasePri as usize;
                    let in_rwx = is_address_in_rwx_section(process_handle, start_address);

                    let mut entropy = 0.0;
                    let mut high_entropy = false;

                    if in_rwx {
                        high_entropy = scan_memory_for_suspicious_patterns(process_handle, start_address, 4096);
                        entropy = if high_entropy {
                            calculate_entropy(&vec![0u8; 4096]) 
                        } else {
                            0.0
                        };
                    }

                    threads.push(ThreadInfo {
                        thread_id: te32.th32ThreadID,
                        start_address,
                        in_rwx,
                        entropy,
                        high_entropy,
                    });
                }

                if Thread32Next(snapshot, &mut te32).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    Ok(threads)
}

fn get_process_memory_usage(pid: u32) -> Option<u64> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;
        let mut mem_counters = PROCESS_MEMORY_COUNTERS::default();
        if GetProcessMemoryInfo(process_handle, &mut mem_counters, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32).is_ok() {
            let _ = CloseHandle(process_handle);
            Some(mem_counters.WorkingSetSize as u64)
        } else {
            let _ = CloseHandle(process_handle);
            None
        }
    }
}

fn filetime_to_systemtime(ft: FILETIME) -> SystemTime {
    let large = (ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64;
    SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(large * 100)
}

fn get_process_creation_time(pid: u32) -> Option<String> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
        let mut creation_time = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();

        if GetProcessTimes(process_handle, &mut creation_time, &mut exit_time, &mut kernel_time, &mut user_time).is_ok() {
            let _ = CloseHandle(process_handle);
            let system_time = filetime_to_systemtime(creation_time);
            let datetime: DateTime<Utc> = system_time.into();
            Some(datetime.to_rfc3339())
        } else {
            let _ = CloseHandle(process_handle);
            None
        }
    }
}

fn list_all_processes() -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            dprintln!("[WARN] Unable to create a snapshot of the processes.");
            return Ok(processes);
        }

        let mut pe32 = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut pe32).is_ok() {
            loop {
                let process_name = String::from_utf16_lossy(
                    &pe32.szExeFile[..pe32.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe32.szExeFile.len())],
                );

                let exe_path = get_process_exe_path(pe32.th32ProcessID).unwrap_or_else(|| "Unknown".to_string());

                let md5_hash = if exe_path != "Unknown" {
                    calculate_md5(&exe_path)
                } else {
                    None
                };

                let sha256_hash = if exe_path != "Unknown" {
                    calculate_sha256(&exe_path)
                } else {
                    None
                };

                let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pe32.th32ProcessID).ok();

                let modules = match list_loaded_modules(pe32.th32ProcessID) {
                    Ok(modules) => modules,
                    Err(_) => Vec::new(),
                };

                let threads = if let Some(handle) = process_handle {
                    scan_threads_in_rwx(pe32.th32ProcessID, handle).unwrap_or_else(|_| Vec::new())
                } else {
                    Vec::new()
                };

                processes.push(ProcessInfo {
                    pid: pe32.th32ProcessID,
                    name: process_name,
                    parent_pid: pe32.th32ParentProcessID,
                    thread_count: pe32.cntThreads,
                    priority: pe32.pcPriClassBase as i32,
                    exe_path,
                    memory_usage: get_process_memory_usage(pe32.th32ProcessID).unwrap_or(0),
                    creation_time: get_process_creation_time(pe32.th32ProcessID).unwrap_or_else(|| "Unknown".to_string()),
                    md5_hash,
                    sha256_hash,
                    modules,
                    threads,
                });

                if let Some(handle) = process_handle {
                    let _ = CloseHandle(handle);
                }

                if Process32NextW(snapshot, &mut pe32).is_err() {
                    break;
                }
            }
        } else {
            dprintln!("[WARN] Unable to retrieve the first process.");
        }

        let _ = CloseHandle(snapshot);
    }

    Ok(processes)
}

pub fn run(full_path: &Path) {
    // Try to create the file, log error if it fails
    let mut file = match File::create(&full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Failed to create file at `{}`: {}", full_path.display(), e);
            return; // Exit early to avoid proceeding with errors
        }
    };

    // List all processes and handle errors if the listing fails
    let processes = match list_all_processes() {
        Ok(p) => p,
        Err(e) => {
            dprintln!("[ERROR] Failed to list processes: {}", e);
            return; // Exit early if we can't list processes
        }
    };

    // Serialize processes to JSON and handle potential serialization errors
    let json_data = match serde_json::to_string_pretty(&processes) {
        Ok(data) => data,
        Err(e) => {
            dprintln!("[ERROR] Failed to serialize processes to JSON: {}", e);
            return; // Exit early if serialization fails
        }
    };

    // Write JSON data to the file, and handle errors if the write fails
    if let Err(e) = file.write_all(json_data.as_bytes()) {
        dprintln!("[ERROR] Failed to write to file `{}`: {}", full_path.display(), e);
        return; // Exit early if writing to the file fails
    }

    dprintln!("[INFO] Process information has been written to: {}", full_path.display());
}
