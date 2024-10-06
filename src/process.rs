//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs::File;
use std::io::{self, Write};
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        System::Diagnostics::ToolHelp::*,
    },
};
use std::path::Path;

pub fn run_ps(filename: &str, path: &Path) {
    // Create the full path
    let full_path = path.join(filename);

    // Try to create the file, log error if it fails
    let mut file = match File::create(&full_path) {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Failed to create file at `{}`: {}", full_path.display(), e);
            return; // Exit early to avoid proceeding with errors
        }
    };

    // Try to get the list of processes, log error if it fails
    let processes = match get_processes() {
        Ok(p) => p,
        Err(e) => {
            dprintln!("[ERROR] Failed to retrieve processes: {}", e);
            return; // Exit early if we can't retrieve processes
        }
    };

    // Loop through each process and try to write its information to the file
    for process in processes {
        if let Err(e) = write_process_info(&mut file, &process) {
            dprintln!(
                "[ERROR] Failed to write process info to file `{}`: {}",
                full_path.display(),
                e
            );
            return; // Exit early if writing process info fails
        }
    }

    dprintln!("[INFO] Process information has been successfully written to: {}", full_path.display());
}

fn get_processes() -> Result<Vec<PROCESSENTRY32>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot.is_invalid() {
            return Err(Error::from_win32());
        }

        let mut processes = Vec::new();
        let mut process_entry = PROCESSENTRY32::default();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut process_entry).is_ok() {
            loop {
                // Clone the current process entry and push it into the vector
                processes.push(process_entry.clone());

                if Process32Next(snapshot, &mut process_entry).is_err() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
        Ok(processes)
    }
}

fn extract_exe_name(raw_name: &[i8; 260]) -> String {
    let end = raw_name.iter().position(|&c| c == 0).unwrap_or(raw_name.len());
    let slice = &raw_name[..end];
    let u8_slice = unsafe { &*(slice as *const [i8] as *const [u8]) };
    String::from_utf8_lossy(u8_slice).into_owned()
}

fn write_process_info<W: Write>(writer: &mut W, process: &PROCESSENTRY32) -> io::Result<()> {
    let exe_file = extract_exe_name(&process.szExeFile);
    write!(
        writer,
        "PID: {}, Parent PID: {}, Executable: {}\n",
        process.th32ProcessID,
        process.th32ParentProcessID,
        exe_file
    )
}

