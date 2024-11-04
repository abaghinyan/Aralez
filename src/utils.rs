//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM cipher
use anyhow::{Error, Result};
use filetime::{set_file_times, FileTime};
use ntfs::{NtfsAttribute, NtfsAttributeType, NtfsFile, NtfsReadSeek};
use rand::RngCore;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::fs::File;
use std::fs::{create_dir_all, OpenOptions};
use std::io;
use std::io::ErrorKind;
use std::io::SeekFrom;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub fn get<T>(
    file: &NtfsFile,
    file_name: &str,
    out_dir: &str,
    fs: &mut T,
    encrypt: Option<&String>,
    ads: &str,
    drive: &str,
) -> Result<(), Error>
where
    T: Read + Seek,
{
    // Check if encryption is required and construct the output file name
    let mut output_file_name = if let Some(ref password) = encrypt {
        if !password.is_empty() {
            let path = Path::new(&file_name);
            let new_file_name = if let Some(extension) = path.extension() {
                format!("{}.enc", path.with_extension(extension).to_string_lossy())
            } else {
                format!("{}.enc", path.to_string_lossy())
            };
            format!("{}{}", out_dir, new_file_name)
        } else {
            format!("{}{}", out_dir, file_name)
        }
    } else {
        format!("{}{}", out_dir, file_name)
    };

    // Try to create the directory, log error if it fails
    if let Err(e) = create_dir_all(
        output_file_name
            .rfind('/')
            .map(|pos| &output_file_name[..pos])
            .unwrap_or(""),
    ) {
        return Err(anyhow::anyhow!(
            "[ERROR] Failed to create directory `{}`: {}",
            out_dir,
            e
        ));
    }

    // Append the Alternate Data Stream (ADS) name if it's not empty
    output_file_name = output_file_name.replace(":", "%3A");
    // Try to open the file for writing, log error if it fails
    let mut output_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_file_name)
    {
        Ok(f) => f,
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            return Ok(()); 
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "[ERROR] Failed to open file `{}` for writing: {}",
                output_file_name,
                e
            ));
        }
    };
    if ads.is_empty() || ads == "" { 
        // Iterate over attributes to find $INDEX_ALLOCATION
        let attributes: Vec<_> = file.attributes().attach(fs).collect::<Result<Vec<_>, _>>()?;
        for attribute in attributes {
            match  attribute.to_attribute() {
                Ok(attr) => {
                    if attr.ty().unwrap() == NtfsAttributeType::IndexAllocation {
                        get_attr(&attr, fs, out_dir)?;
                    }
                },
                Err(e) => dprintln!("[ERROR] Can't getting attriputes"),
            } 
        }
    }

    // Try to get the data item, log warning if it does not exist
    let data_item = match file.data(fs, ads) {
        Some(Ok(item)) => item,
        Some(Err(e)) => {
            return Err(anyhow::anyhow!(
                "[ERROR] Failed to retrieve data for `{}`: {}",
                file_name,
                e
            ));
        }
        None => {
            return Err(anyhow::anyhow!("[WARN] The file {} does not have a $DATA attribute.", output_file_name));
        }
    };
    let data_attribute = match data_item.to_attribute() {
        Ok(attr) => attr,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "[ERROR] Failed to retrieve attribute for `{}`: {}",
                file_name,
                e
            ));
        }
    };

    let mut data_value = match data_attribute.value(fs) {
        Ok(val) => val,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "[ERROR] Failed to retrieve data value for `{}`: {}",
                file_name,
                e
            ));
        }
    };

    dprintln!(
        "[INFO] Saving {} bytes of data in `{}`",
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
                return Err(anyhow::anyhow!(
                    "[ERROR] Failed to write nonce to `{}`",
                    output_file_name
                ));
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
                        return Err(anyhow::anyhow!("[ERROR] Encryption failed: {}", e));
                    }
                };

                // Write the encrypted chunk to the output file
                if output_file.write_all(&encrypted_chunk).is_err() {
                    return Err(anyhow::anyhow!(
                        "[ERROR] Failed to write encrypted chunk to `{}`",
                        output_file_name
                    ));
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
                    return Err(anyhow::anyhow!(
                        "[ERROR] Failed to write chunk to `{}`",
                        output_file_name
                    ));
                }
            }
        }
    } else {
        // No encryption, write the file normally in chunks
        if file_name == "/$Boot" {
            output_file.write_all(&get_boot(&drive).unwrap()).unwrap();
        } else {
            while let Ok(bytes_read) = data_value.read(fs, &mut read_buf) {
                if bytes_read == 0 {
                    break;
                }

                let chunk = if ads.is_empty() || ads == "" {
                    &read_buf[..bytes_read]
                } else if !leading_zeros_skipped {
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
                    return Err(anyhow::anyhow!(
                        "[ERROR] Failed to write chunk to `{}`",
                        output_file_name
                    ));
                }
            }
        }
    }
    // Retrieve timestamps from NtfsFile (replace these method calls with the actual methods from NtfsFile)
    if let Ok(file_std_info) = file.info() {
        let modified_time =
            nt_timestamp_to_system_time(file_std_info.modification_time().nt_timestamp());
        let accessed_time = nt_timestamp_to_system_time(file_std_info.access_time().nt_timestamp());

        // Convert SystemTime to FileTime
        let modified_file_time = FileTime::from_system_time(modified_time);
        let accessed_file_time = FileTime::from_system_time(accessed_time);

        // Apply these timestamps to output_file
        set_file_times(&output_file_name, accessed_file_time, modified_file_time)
            .map_err(|e| anyhow::anyhow!("[ERROR] Failed to set file timestamps: {}", e))?;
    }
    match output_file.flush() {
        Ok(_) => {
            dprintln!("[INFO] Data successfully saved to `{}`", output_file_name);
            return Ok(());
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "[ERROR] Problem to save `{}` file: {:?}",
                output_file_name,
                e
            ))
        }
    };
}

fn get_attr <T>(attr: &NtfsAttribute, fs: &mut T, out_dir: &str) -> Result<(), Error> 
where
T: Read + Seek,
{
    let attr_name = attr.name()?.to_string_lossy().to_string();
    dprintln!("[INFO] Found $INDEX_ALLOCATION attribute : `{}`", &attr_name);

    let attr_path = format!("{}/{}", out_dir, &attr_name);
    let mut attr_value = attr.value(fs)?;

    let mut output_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&attr_path)
    {
        Ok(f) => f,
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            return Ok(()); 
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "[ERROR] Failed to open file `{}` for writing: {}",
                &attr_path,
                e
            ));
        }
    };
    dprintln!(
        "[INFO] Saving {} bytes of index attribute data in `{}`",
        attr_value.len(),
        &attr_path
    );
    let mut read_buf = [0u8; 4096];

    while let Ok(bytes_read) = attr_value.read(fs, &mut read_buf) {
        if bytes_read == 0 {
            // End of file reached
            break;
        }
        if output_file.write_all(&read_buf[..bytes_read]).is_err() {
            return Err(anyhow::anyhow!(
                "[ERROR] Failed to write chunk to `{}`",
                attr_path
            ));
        }
    }



    Ok(())
}

// Function to convert NT timestamp (u64) to SystemTime
fn nt_timestamp_to_system_time(nt_timestamp: u64) -> SystemTime {
    // NT Epoch: January 1, 1601 -> UNIX Epoch: January 1, 1970 (difference in seconds)
    let nt_epoch_to_unix_epoch = Duration::from_secs(11644473600); // 369 years in seconds
    let timestamp_duration = Duration::from_nanos(nt_timestamp * 100); // Convert to nanoseconds
    UNIX_EPOCH + timestamp_duration - nt_epoch_to_unix_epoch
}

fn get_boot(drive_letter: &str) -> Result<Vec<u8>, Error> {
    let drive_path = format!("\\\\.\\{}:", drive_letter); // Raw access to the drive

    // Check if the drive exists before attempting to open it
    if Path::new(&format!("{}:\\", drive_letter)).exists() {
        let mut file = File::open(&drive_path).unwrap();
        let mut boot_sector = vec![0u8; 8192];

        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut boot_sector)?;

        return Ok(boot_sector);
    }

    Err(anyhow::anyhow!(
        "[ERROR] Drive {} does not exist",
        drive_letter
    ))
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
