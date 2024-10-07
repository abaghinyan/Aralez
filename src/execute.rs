//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

mod network_info;
mod process;
mod process_details;

use std::process::{Command, Stdio};
use std::fs;
use std::io::{self, Write};
use std::fs::{File, remove_file};
use std::path::{Path, PathBuf};

pub fn run_system(tool_name: &str, args: &[&str], output_filename: &str, output_path: &str) {
    dprintln!("[INFO] Execution of {}", tool_name);

    // Create the full path for the output file
    let output_file_path = Path::new(output_path).join(output_filename);

    // Execute the command
    let output = Command::new(tool_name)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Err(e) = output {
        dprintln!("[ERROR] Failed to execute tool `{}`: {}", tool_name, e);
        return; // Return early to continue the main process without stopping
    }

    let output = output.unwrap(); // Safe unwrap because we handled the error above

    // Check if the execution was successful
    if !output.status.success() {
        dprintln!(
            "[ERROR] Command `{}` failed with status: {}",
            tool_name,
            output.status
        );
        return; // Continue without further execution if the command failed
    }

    // Write the output to the specified file
    if let Err(e) = fs::File::create(&output_file_path).and_then(|mut file| file.write_all(&output.stdout)) {
        dprintln!("[ERROR] Failed to write tool output to file `{}`: {}", output_file_path.display(), e);
        return; // Return early if writing the output fails
    }

    dprintln!("[INFO] Tool output has been saved to: {}", output_file_path.display());
    dprintln!("[INFO] Execution of {} completed", tool_name);
}

pub fn run_internal(tool_name:&str, output_filename: &str, output_path: &str) {
    dprintln!("[INFO] Execution of {}", tool_name);

    // Create the full path for the output file
    let output_file_path = Path::new(output_path).join(output_filename);

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
            dprintln!("[ERROR] Internal tool {} not found", tool_name);
            return;
        }
    }
    dprintln!("[INFO] Tool output has been saved to: {}", output_path);
    dprintln!("[INFO] Execution of {} completed", tool_name);
}

pub fn run_external(
    exe_bytes: &[u8], 
    filename: &str, 
    output_path: &str, 
    output_file: &str, 
    args: &[&str]
) {
    dprintln!("[INFO] Execution of {}", filename);

    // Save the executable to a temporary file
    let temp_exe_path = match save_to_temp_file(filename, exe_bytes, output_path) {
        Ok(path) => path,  // If saving succeeds, use the path
        Err(e) => {
            dprintln!("[ERROR] Failed to save to temp file: {}", e);
            return;  // Exit the function if there's an error
        }
    };

    // Execute the command and wait for completion
    let output = Command::new(&temp_exe_path)
        .args(args)
        .output();

    if let Err(e) = output {
        dprintln!("[ERROR] Failed to execute file: {}", e);
        return; // Exit if execution fails
    }

    let output = output.unwrap(); // Safe because we already handled the error

    // Check the exit status
    if !output.status.success() {
        dprintln!("[ERROR] Command failed with exit code: {:?}", output.status.code());
    }

    // Save the result to the specified output path
    if let Err(e) = save_output_to_file(&output.stdout, output_file, output_path) {
        dprintln!("[ERROR] Failed to save output to file: {}", e);
    }

    // Clean up the temporary file
    if let Err(e) = cleanup_temp_file(&temp_exe_path) {
        dprintln!("[ERROR] Failed to clean up temp file: {}", e);
    }

    dprintln!("[INFO] Tool output has been saved to: {}", output_path);
    dprintln!("[INFO] Execution of {} completed", filename);
}

pub fn get_bin(name: String) -> Result<&'static [u8], anyhow::Error> {
    let exe_bytes: &[u8] = match name.as_str() {
        "autorunsc.exe" => include_bytes!("../tools/autorunsc.exe"),
        "handle.exe" => include_bytes!("../tools/handle.exe"),
        "tcpvcon.exe" => include_bytes!("../tools/tcpvcon.exe"),
        "pslist.exe" => include_bytes!("../tools/pslist.exe"),
        "Listdlls.exe" => include_bytes!("../tools/Listdlls.exe"),
        "PsService.exe" => include_bytes!("../tools/PsService.exe"),
        _ => return Err(anyhow::anyhow!(format!("[ERROR] {} not found", name))),
    };

    Ok(exe_bytes)
}

fn save_to_temp_file(_filename: &str, exe_bytes: &[u8], output_path: &str) -> io::Result<PathBuf> {
    // Get the temp directory
    let output_file_path = Path::new(output_path).join(_filename);

    // Write the bytes to the temp file
    let mut file = File::create(&output_file_path)?;
    file.write_all(exe_bytes)?;

    // Make the file executable on Unix-like systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o755);
        file.set_permissions(permissions)?;
    }

    Ok(output_file_path)
}

fn save_output_to_file(output: &[u8], output_filename: &str, output_path: &str) -> io::Result<()> {
    let output_file_path = Path::new(output_path).join(output_filename);
    let mut file = File::create(output_file_path)?;
    file.write_all(output)?;
    file.flush()?;
    Ok(())
}

fn cleanup_temp_file(temp_exe_path: &Path) -> io::Result<()> {
    dprintln!("[INFO] {:?}", temp_exe_path);
    if temp_exe_path.exists() {
        remove_file(temp_exe_path)?;
    }
    Ok(())
}

