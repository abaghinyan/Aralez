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

pub fn get<T>(file: &NtfsFile, filename: &str, out_dir: &str, fs: &mut T, encrypt: Option<&String>, ads: &str)
where
    T: Read + Seek,
{
    // Get the file name or use the provided filename, log errors if they occur
    let (file_name, _) = match get_object_name(file, fs) {
        Ok(name) => (name, out_dir),
        Err(_) => (filename.to_string(), out_dir),
    };

    // Try to create the directory, log error if it fails
    if let Err(e) = create_dir_all(out_dir) {
        dprintln!("[ERROR] Failed to create directory `{}`: {}", out_dir, e);
        return;
    }

    // Check if encryption is required and construct the output file name
    let mut output_file_name = if let Some(ref password) = encrypt {
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

    // Append the Alternate Data Stream (ADS) name if it's not empty
    if !(ads.is_empty() || ads == "") {
        output_file_name.push_str(&format!("%3A{}", ads));
    }

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
    let data_item = match file.data(fs, ads) {
        Some(Ok(item)) => item,
        Some(Err(e)) => {
            dprintln!("[ERROR] Failed to retrieve data for `{}`: {}", file_name, e);
            return;
        }
        None => {
            // dprintln!("[WARN] The file does not have a `{}` $DATA attribute.", data_stream_name);
            return;
        }
    };

    let data_attribute = match data_item.to_attribute() {
        Ok(attr) => attr,
        Err(e) => {
            dprintln!("[ERROR] Failed to retrieve attribute for `{}`: {}", file_name, e);
            return;
        }
    };

    let mut data_value = match data_attribute.value(fs) {
        Ok(val) => val,
        Err(e) => {
            dprintln!("[ERROR] Failed to retrieve data value for `{}`: {}", file_name, e);
            return;
        }
    };

    dprintln!(
        "[INFO] Saving {} bytes of data in `{}`...",
        data_value.len(),
        output_file_name
    );

    // Buffer for reading chunks of the file
    let mut read_buf = [0u8; 4096];
    let mut leading_zeros_skipped = false;

    // Stream data based on encryption
    if let Some(ref password) = encrypt {
        if !password.is_empty() {
            // Derive the encryption key using SHA256
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let key_bytes = hasher.finalize();
            let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes[..32]); // AES-256 requires a 32-byte key
            let cipher = Aes256Gcm::new(cipher_key);

            // Generate a nonce (unique for each message)
            let mut nonce = [0u8; 12]; // 96-bit nonce for AES-GCM
            OsRng.fill_bytes(&mut nonce);
            let nonce = Nonce::from_slice(&nonce);

            // Write the nonce to the file before writing encrypted data
            if output_file.write_all(nonce).is_err() {
                dprintln!("[ERROR] Failed to write nonce to `{}`", output_file_name);
                return;
            }

            // Stream data, encrypt each chunk, and write it to the file
            while let Ok(bytes_read) = data_value.read(fs, &mut read_buf) {
                if bytes_read == 0 {
                    break;
                }

                let chunk = if !leading_zeros_skipped {
                    if let Some(non_zero_pos) = read_buf.iter().position(|&b| b != 0) {
                        leading_zeros_skipped = true;
                        &read_buf[non_zero_pos..bytes_read]
                    } else {
                        continue;
                    }
                } else {
                    &read_buf[..bytes_read]
                };

                let encrypted_chunk = match cipher.encrypt(nonce, chunk) {
                    Ok(ct) => ct,
                    Err(e) => {
                        dprintln!("[ERROR] Encryption failed: {}", e);
                        return;
                    }
                };

                // Write the encrypted chunk to the output file
                if output_file.write_all(&encrypted_chunk).is_err() {
                    dprintln!("[ERROR] Failed to write encrypted chunk to `{}`", output_file_name);
                    return;
                }
            }
        } else {
            // No encryption, stream and write data in chunks
            while let Ok(bytes_read) = data_value.read(fs, &mut read_buf) {
                if bytes_read == 0 {
                    break;
                }

                let chunk = if !leading_zeros_skipped {
                    if let Some(non_zero_pos) = read_buf.iter().position(|&b| b != 0) {
                        leading_zeros_skipped = true;
                        &read_buf[non_zero_pos..bytes_read]
                    } else {
                        continue;
                    }
                } else {
                    &read_buf[..bytes_read]
                };

                if output_file.write_all(chunk).is_err() {
                    return;
                }
            }
        }
    } else {
        // No encryption, write the file normally in chunks
        while let Ok(bytes_read) = data_value.read(fs, &mut read_buf) {
            if bytes_read == 0 {
                break;
            }

            let chunk = if !leading_zeros_skipped {
                if let Some(non_zero_pos) = read_buf.iter().position(|&b| b != 0) {
                    leading_zeros_skipped = true;
                    &read_buf[non_zero_pos..bytes_read]
                } else {
                    continue;
                }
            } else {
                &read_buf[..bytes_read]
            };

            if output_file.write_all(chunk).is_err() {
                return;
            }
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

pub fn get_level_path_pattern(path: &str, level: usize) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    
    if level < parts.len() {
        // Join the parts up to the requested level (inclusive)
        Some(parts[..=level].join("/"))
    } else {
        if path.ends_with("**") {
            return Some(path.to_string())
        }
        None // Return None if the level doesn't exist
    }
}

pub fn remove_trailing_backslashes(input: &str) -> String {
    if input.ends_with("\\") {
        input.strip_suffix("\\").unwrap_or(input).to_string()
    } else {
        input.to_string()
    }
}