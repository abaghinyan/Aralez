//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::process::{Command, Stdio};
use std::fs;
use std::path::Path;
use std::io::{self, Write};

pub fn run_tool(tool_name: &str, args: &[&str], output_filename: &str, output_path: &str) -> io::Result<()> {
    // Create the full path for the output file
    let output_file_path = Path::new(output_path).join(output_filename);

    // Execute the command
    let output = Command::new(tool_name)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    // Check if the execution was successful
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Command `{}` failed with status: {}", tool_name, output.status),
        ));
    }

    // Write the output to the specified file
    let mut file = fs::File::create(&output_file_path)?;
    file.write_all(&output.stdout)?;

    dprintln!("[INFO] Tool output has been saved to: {}", output_file_path.display());
    
    Ok(())
}