//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use anyhow::Result;
use ntfs::{NtfsFile, NtfsReadSeek, NtfsError, structured_values::NtfsFileNamespace};
use std::fs::{create_dir_all, OpenOptions};
use std::io::{Read, Seek, Write};
use std::fs;
use std::path::Path;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM cipher
use rand::RngCore;
use sha2::{Sha256, Digest};
use regex::Regex;
use std::env;
use std::io;

pub fn get<T>(file: &NtfsFile, filename: &str, out_dir: &str, fs: &mut T, encrypt: Option<&String>)
where
    T: Read + Seek,
{
    // Get the file name or use the provided filename, log errors if they occur
    let (file_name, data_stream_name) = match get_object_name(file, fs) {
        Ok(name) => (name, out_dir),
        Err(_) => (filename.to_string(), out_dir),
    };

    // Try to create the directory, log error if it fails
    if let Err(e) = create_dir_all(out_dir) {
        dprintln!("[ERROR] Failed to create directory `{}`: {}", out_dir, e);
        return;
    }

    // Check if encryption is required and construct the output file name
    let output_file_name = if let Some(ref password) = encrypt {
        if !password.is_empty() {
            let path = Path::new(&file_name);
            let new_file_name = if let Some(extension) = path.extension() {
                format!("{}.enc", path.with_extension(extension).to_string_lossy())
            } else {
                format!("{}.enc", path.to_string_lossy())
            };
            format!("{}/{}", out_dir, new_file_name)
        } else {
            format!("{}/{}", out_dir, file_name)
        }
    } else {
        format!("{}/{}", out_dir, file_name)
    };

    // Try to open the file for writing, log error if it fails
    let mut output_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_file_name)
    {
        Ok(f) => f,
        Err(e) => {
            dprintln!("[ERROR] Failed to open file `{}` for writing: {}", output_file_name, e);
            return;
        }
    };

    // Try to get the data item, log warning if it does not exist
    let data_item = match file.data(fs, "") {
        Some(Ok(item)) => item,
        Some(Err(e)) => {
            dprintln!("[ERROR] Failed to retrieve data for `{}`: {}", data_stream_name, e);
            return;
        }
        None => {
            dprintln!("[WARN] The file does not have a `{}` $DATA attribute.", data_stream_name);
            return;
        }
    };

    let data_attribute = match data_item.to_attribute() {
        Ok(attr) => attr,
        Err(e) => {
            dprintln!("[ERROR] Failed to retrieve attribute for `{}`: {}", data_stream_name, e);
            return;
        }
    };

    let mut data_value = match data_attribute.value(fs) {
        Ok(val) => val,
        Err(e) => {
            dprintln!("[ERROR] Failed to retrieve data value for `{}`: {}", data_stream_name, e);
            return;
        }
    };

    dprintln!(
        "[INFO] Saving {} bytes of data in `{}`...",
        data_value.len(),
        output_file_name
    );

    let mut buf = Vec::new();
    let mut read_buf = [0u8; 4096];
    while let Ok(bytes_read) = data_value.read(fs, &mut read_buf) {
        if bytes_read == 0 {
            break;
        }
        buf.extend_from_slice(&read_buf[..bytes_read]);
    }

    if let Some(ref password) = encrypt {
        if !password.is_empty() {
            // Derive the key and handle encryption
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let key_bytes = hasher.finalize();
            let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes[..32]); // AES-256 requires a 32-byte key
            let cipher = Aes256Gcm::new(cipher_key);

            let mut nonce = [0u8; 12]; // 96-bits; unique per message
            OsRng.fill_bytes(&mut nonce);

            let nonce = Nonce::from_slice(&nonce);
            let ciphertext = match cipher.encrypt(nonce, buf.as_ref()) {
                Ok(ct) => ct,
                Err(e) => {
                    dprintln!("[ERROR] Encryption failed: {}", e);
                    return;
                }
            };

            // Write nonce and ciphertext to the file
            if output_file.write_all(nonce).is_err() || output_file.write_all(&ciphertext).is_err() {
                dprintln!("[ERROR] Failed to write encrypted data to `{}`", output_file_name);
                return;
            }
        } else {
            // Write the file normally if no encryption is needed
            if output_file.write_all(&buf).is_err() {
                dprintln!("[ERROR] Failed to write data to `{}`", output_file_name);
                return;
            }
        }
    } else {
        // No encryption, write the file normally
        if output_file.write_all(&buf).is_err() {
            dprintln!("[ERROR] Failed to write data to `{}`", output_file_name);
            return;
        }
    }

    dprintln!("[INFO] Data successfully saved to `{}`", output_file_name);
}


/// Retrieves the name of the file from the NTFS $FILE_NAME attribute.
pub fn get_object_name<T: Read + Seek>(file: &NtfsFile, fs: &mut T) -> Result<String, NtfsError> {
    if let Some(result) = file.name(fs, Some(NtfsFileNamespace::Win32), None) {
        match result {
            Ok(name) => Ok(name.name().to_string_lossy().to_string()),
            Err(err) => Err(err),
        }
    } else {
        if let Some(result) = file.name(fs, Some(NtfsFileNamespace::Posix), None) {
            match result {
                Ok(name) => Ok(name.name().to_string_lossy().to_string()),
                Err(err) => Err(err),
            }
        } else {
            if let Some(result) = file.name(fs, Some(NtfsFileNamespace::Win32AndDos), None) {
                match result {
                    Ok(name) => Ok(name.name().to_string_lossy().to_string()),
                    Err(err) => Err(err),
                }
            } else {
                Err(NtfsError::AttributeNotFound {
                    position: file.position(),
                    ty: ntfs::NtfsAttributeType::FileName,
                })
            }
        }

    }
}

pub fn ensure_directory_exists(path: &str) -> std::io::Result<()> {
    let path = Path::new(path);
    if !path.exists() {
        fs::create_dir_all(path)?;
        dprintln!("[INFO] Created output directory: {}", path.display());
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

    let mut replaced_str = result.into_owned(); // Convert to owned String

    // Remove the "C:\" from the beginning if it exists
    if replaced_str.starts_with("C:\\") {
        replaced_str = replaced_str.strip_prefix("C:\\").unwrap().to_string();
    }
    replaced_str
}

pub fn remove_dir_all(path: &str) -> io::Result<()> {
    let path = Path::new(path);  // Convert the string to a Path
    if path.is_dir() {
        // Iterate over all entries in the directory
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            // Recursively remove directory contents or remove the file
            if entry_path.is_dir() {
                // Convert Path to &str safely and recursively call remove_dir_all
                if let Some(entry_str) = entry_path.to_str() {
                    remove_dir_all(entry_str)?;  // Recursively call the function and propagate errors
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

pub fn get_subfolder_level(path: &str) -> usize {
    // Count the number of '/' characters in the path
    path.matches('/').count() 
}

pub fn get_level_path(path: &str, level: usize) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    
    if level < parts.len() {
        // Join the parts up to the requested level (inclusive)
        Some(parts[..=level].join("/"))
    } else {
        None // Return None if the level doesn't exist
    }
}

pub fn get_subfolder_level_regex(path: &str) -> usize {
    // Count the number of '/' characters in the path
    path.matches("\\\\").count()
}

pub fn get_level_path_regex(path: &str, level: usize) -> Option<String> {
    let parts: Vec<&str> = path.split("\\\\").collect();
    
    if level < parts.len() {
        // Join the parts up to the requested level (inclusive)
        Some(parts[..=level].join("\\\\"))
    } else {
        None // Return None if the level doesn't exist
    }
}