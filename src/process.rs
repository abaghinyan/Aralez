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

pub fn run_ps(filename: &str, path: &Path) -> io::Result<()> {
    let full_path = path.join(filename);
    let mut file = File::create(&full_path)?;
    
    let processes = get_processes()?;
    for process in processes {
        write_process_info(&mut file, &process)?;
    }

    Ok(())
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

