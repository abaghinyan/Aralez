//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

mod network_info;
mod process;
mod process_details;

use crate::config::ExecType;
use crate::resource::extract_resource;

use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::fs::{File, remove_file};
use std::path::{Path, PathBuf};
use wait_timeout::ChildExt;
use std::time::Duration;

static TIMEOUT: u64 = 60;

pub fn run_internal(tool_name:&str, output_filename: &str) -> Option<String> {
    dprintln!("[INFO] > `{}` | Starting execution", tool_name);

    // Create the full path for the output file
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
            network_info::run_network_info(&output_file_path);
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

pub fn run (
    mut name: String, 
    args: &[&str],
    exec_type: ExecType,
    exe_bytes: Option<&[u8]>, 
    output_path: Option<&str>, 
    output_file: &str
) -> Option<String> {
    let mut display_name = name.clone();
    if exec_type == ExecType::External {
        // Save the executable to a temporary file
        let buffer = match exe_bytes {
            Some(bytes) => bytes,
            None => {
                dprintln!("[ERROR] > `{}` | Content of the external file not found", name);
                return None;
            },
        };
        let path = match output_path {
            Some(p) => p,
            None => {
                dprintln!("[ERROR] > `{}` | The output path for the executable not found", name);
                return None;
            },
        };
        let temp_exe_path = match save_to_temp_file(&name, buffer, path) {
            Ok(path) => path,  // If saving succeeds, use the path
            Err(e) => {
                dprintln!("[ERROR] > `{}` | Failed to save to temp file: {}", name, e);
                return None;  // Exit the function if there's an error
            }
        };
        
        name = temp_exe_path.to_string_lossy().to_string();

        // Get the filename
        let tmp_display_name = temp_exe_path.file_name().and_then(|os_str| os_str.to_str()).unwrap_or(&name.as_str());
        display_name = tmp_display_name.to_string();
    }

    // Execute the command and wait for completion
    let mut child = match Command::new(&name)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            dprintln!("[INFO] > `{}` ({}) | Starting execution with args: {:?}", display_name, &child.id(), args);
            child
        }
        Err(e) => {
            dprintln!("[ERROR] > `{}` | Failed to spawn process: {}", display_name, e);
            return None;
        }
    };
    let one_sec = Duration::from_secs(TIMEOUT);
    let _status_code = match child.wait_timeout(one_sec).unwrap() {
        Some(status) => status.code(),
        None => {
            dprintln!("[WARN] > `{}` | Execution timed out", display_name);
            child.kill().unwrap();
            child.wait().unwrap().code()
        }
    };

    let pid = child.id();

    let output = match child.wait_with_output() {
        Ok(output) => {
            if !output.status.success() {
                let stderr_msg = String::from_utf8_lossy(&output.stderr);
                dprintln!("[ERROR] > `{}` ({}) | Command failed: {}", display_name, pid, stderr_msg.trim());
            }
            output
        }
        Err(e) => {
            dprintln!("[ERROR] > `{}` ({}) | Failed to execute: {}", display_name, pid, e);
            return None;
        }
    };

    dprintln!("[INFO] > `{}` ({}) | Exit code: {:?}", display_name, pid, output.status.code().unwrap_or(-1));

    // Save the result to the specified output path
    if let Err(e) = save_output_to_file(&output.stdout, output_file) {
        dprintln!("[ERROR] > `{}` ({}) | Failed to save output to file: {}", display_name, pid, e);
    }

    if exec_type == ExecType::External {
        // Clean up the temporary file
        if let Err(e) = cleanup_temp_file(&name) {
            dprintln!("[ERROR] > `{}` ({}) | Failed to clean up temp file: {}", display_name, pid, e);
        }
    }

    dprintln!("[INFO] > `{}` ({}) | The output has been saved to: {}", display_name, pid, output_file);
    dprintln!("[INFO] > `{}` ({}) | Execution completed", display_name, pid);

    return Some(String::from_utf8(output.stdout).unwrap_or("".to_string()));
}

pub fn get_list_tools () -> Vec<&'static str> {
    vec![
        "autorunsc.exe",
        "handle.exe",
        "tcpvcon.exe",
        "pslist.exe",
        "Listdlls.exe",
        "PsService.exe",
        "pipelist.exe",
        "winpmem_mini_rc2.exe"
    ]
}

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
            Ok(bytes) => bytes, // Return owned Vec<u8> from extract_resource
            Err(_) => return Err(anyhow::anyhow!(format!("[ERROR] {} not found", name))),
        },
    };

    Ok(exe_bytes)
}

fn save_to_temp_file(_filename: &String, exe_bytes: &[u8], output_path: &str) -> io::Result<PathBuf> {
    // Get the temp directory
    let output_file_path = Path::new(output_path).join(_filename);

    // Write the bytes to the temp file
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