//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use regex::Regex;
use std::env;
use std::fs;
use std::io;
use std::path::Path;


pub fn ensure_directory_exists(path: &str) -> std::io::Result<()> {
    let path = Path::new(path);
    if !path.exists() {
        fs::create_dir_all(path)?;
        dprintln!("[INFO] Directory {} is created", path.display());
    }
    Ok(())
}

pub fn replace_env_vars(input: &str) -> String {
    // Regex pattern to match %VAR_NAME% or %SYSTEM_VAR_NAME%
    let re = Regex::new(r"%([^%]+)%").unwrap();

    // Replace each match with the corresponding environment variable value
    let result = re.replace_all(input, |caps: &regex::Captures| {
        let var_name = &caps[1];
        env::var(var_name).unwrap_or_else(|_| format!("%{}%", var_name))
    });

    let replaced_str = result.into_owned(); // Convert to owned String
    let regex = Regex::new(r"^[A-Za-z]:\\").unwrap(); // Match a single letter at the start followed by :\
    let replaced_str = regex.replace(&replaced_str, r"\");

    replaced_str.to_string()
}

pub fn remove_dir_all(path: &str) -> io::Result<()> {
    let path = Path::new(path); // Convert the string to a Path
    if path.is_dir() {
        // Iterate over all entries in the directory
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            // Recursively remove directory contents or remove the file
            if entry_path.is_dir() {
                // Convert Path to &str safely and recursively call remove_dir_all
                if let Some(entry_str) = entry_path.to_str() {
                    remove_dir_all(entry_str)?; // Recursively call the function and propagate errors
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid UTF-8 sequence in path",
                    ));
                }
            } else {
                // If the entry is a file, remove it
                fs::remove_file(&entry_path)?;
            }
        }
        // Once the directory is empty, remove the directory itself
        fs::remove_dir(path)?;
    }
    Ok(())
}

pub fn remove_trailing_slash(input: String) -> String {
    input.strip_suffix('/').unwrap_or(&input).to_string()
}

pub fn split_path(input: &str) -> (String, String) {
    if let Some((path, last_segment)) = input.rsplit_once('/') {
        (path.to_string(), last_segment.to_string())
    } else {
        (String::new(), input.to_string())
    }
}
