//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs::{File, remove_file};
use std::io::{self, Write};
use std::process::Command;
use std::path::{Path, PathBuf};

pub fn execute(exe_bytes: &[u8], _filename: &str, output_path: &str, output_file: &str, args: &[&str]) -> io::Result<()> {
    
    // Save the executable to a temporary file
    let temp_exe_path = save_to_temp_file(_filename, exe_bytes, output_path)?;
    // Execute the temporary executable with the provided arguments and capture the output
    let output: std::process::Output = Command::new(&temp_exe_path)
        .args(args)
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to execute file: {}", e)))?;

    // Save the result to the specified output path
    save_output_to_file(&output.stdout, output_file, output_path)?;
    
    // Clean up the temporary file
    cleanup_temp_file(&temp_exe_path)?;
    
    Ok(())
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
    dprintln!("{:?}", temp_exe_path);
    if temp_exe_path.exists() {
        remove_file(temp_exe_path)?;
    }
    Ok(())
}