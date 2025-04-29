#[cfg(target_os = "windows")]
pub mod windows_os {
    pub use crate::utils::ensure_directory_exists;

    pub use std::io;
    pub use std::path::Path;
}

#[cfg(target_os = "windows")]
use windows_os::*;

use crate::config::SectionConfig;
use crate::reader::sector::SectorReader;
use glob::Pattern;
use std::collections::HashSet;
use std::fs::File;
use std::u64;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::io::ErrorKind;
use std::io::SeekFrom;
use std::io::{Read, Seek, Write, BufReader};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM cipher
use anyhow::{Error, Result};
use chrono::{DateTime, Local};
use std::fs::{create_dir_all, OpenOptions};
use sha2::{Digest, Sha256};
use filetime::{set_file_handle_times, FileTime};
use ntfs::{Ntfs, NtfsAttribute, NtfsAttributeType, NtfsFile, NtfsReadSeek};
use rand::RngCore;

use super::fs::Node;

#[cfg(target_os = "windows")]
/// Function to check if a partition is NTFS by looking for the NTFS signature
fn is_ntfs_partition<T: Read + Seek>(reader: &mut T) -> io::Result<bool> {
    const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
    let mut boot_sector = [0u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    match reader.read_exact(&mut boot_sector) {
        Ok(_) => Ok(&boot_sector[3..11] == NTFS_SIGNATURE),
        Err(_) => Ok(false),
    }
}

pub fn initialize_ntfs<T: Read + Seek>(fs: &mut T) -> Result<Ntfs> {
    match Ntfs::new(fs) {
        Ok(mut ntfs) => {
            ntfs.read_upcase_table(fs)?;
            Ok(ntfs)
        },
        Err(_) => Err(anyhow::anyhow!("[WARN] The current drive is not an NTFS partition")),
    }
}

/// Process all NTFS drives except the C drive
#[cfg(target_os = "windows")]
pub fn process_all_drives(section_config: &mut SectionConfig, root_output: &str) -> Result<()> {
    use super::fs::process_drive_artifacts;

    let ntfs_drives = list_ntfs_drives()?;

    'for_drive: for drive in ntfs_drives {
        if let Some(iter_drives) = &section_config.exclude_drives {
            for iter_drive in iter_drives {
                if drive.starts_with(iter_drive) {
                    continue 'for_drive;
                }
            }
        }
        let drive_letter = drive.chars().next().unwrap();
        let output_folder  = if root_output.contains("{{drive}}") {
            root_output.replace("{{drive}}", &drive_letter.to_string())
        } else {
            format!("{}\\{}", root_output, drive_letter)
        };
        ensure_directory_exists(&output_folder)?;
        process_drive_artifacts(&drive, section_config, &output_folder)?;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn list_ntfs_drives() -> io::Result<Vec<String>> {
    let mut ntfs_drives = Vec::new();

    // Loop through the drives from A to Z and check if they are NTFS
    for letter in 'A'..='Z' {
        let drive = format!("{}:\\", letter);

        // Check if the drive exists before trying to open it
        if Path::new(&drive).exists() {
            // Try to open the drive in raw mode to check if it's NTFS
            let drive_path = format!("\\\\.\\{}:", letter);
            if let Ok(mut file) = File::open(&drive_path) {
                // Check if the partition is NTFS
                if is_ntfs_partition(&mut file)? {
                    // If it's NTFS, add it to the list
                    ntfs_drives.push(drive);
                }
            }
        }
    }
    Ok(ntfs_drives)
}

#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub file_record_number: u64,
}

fn process_all_directory(
    fs: &mut BufReader<SectorReader<File>>,
    ntfs: &Ntfs,
    file: &NtfsFile<'_>,
    obj_name: String,
    current_path: &str,
    destination_folder: &str,
    drive: &str,
    encrypt: Option<String>,
    max_size: Option<u64>,
    success_files_count: &mut u32
) -> Result<HashSet<String>> {
    let index = file.directory_index(fs)?;
    let mut iter = index.entries();
    let mut entries = Vec::new();
    let mut local_visited_files: HashSet<String> = HashSet::new();
    // Collect all entries into a vector
    while let Some(entry_result) = iter.next(fs) {
        match entry_result {
            Ok(entry) => {
                let name = entry
                    .key()
                    .unwrap()
                    .unwrap()
                    .name()
                    .to_string_lossy()
                    .to_string();
                let file_record_number = entry.file_reference().file_record_number();
                if name != "." {
                    entries.push(Entry {
                        name,
                        file_record_number,
                    });
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    for entry in entries {
        let new_path = format!("{}/{}", current_path, entry.name);
        if let Ok(sub_file) = ntfs.file(fs, entry.file_record_number) {
            if sub_file.is_directory() {
                if let Err(e) = process_all_directory(
                    fs,
                    ntfs,
                    &sub_file,
                    obj_name.clone(),
                    &new_path,
                    destination_folder,
                    drive,
                    encrypt.clone(),
                    max_size,
                    success_files_count
                ){
                    dprintln!("[ERROR] Processing subdirectory: {:?}", e);
                }
            } else {
                let obj_name_parts = obj_name.split_once(':');
                let (obj_name_san, ads) = match obj_name_parts {
                    Some((left, right)) => {
                        let left_string = left.to_string(); // Create a variable for the `String`
                        (left_string, right) // Return the `String` itself, not a reference to it
                    }
                    None => (obj_name.to_string(), ""), // Ensure consistency with String type
                };
                let mut path_check = new_path.clone();
                if !(ads.is_empty() || ads == "") {
                    path_check = format!("{}:{}", path_check, ads);
                }
                if Pattern::new(&obj_name_san.as_str().to_lowercase())
                    .unwrap()
                    .matches(&path_check.as_str().to_lowercase())
                {
                    // check size
                    let mut size_ok = true;
                    if let Some(msize) = max_size {
                        if get_file_size(&sub_file, fs) as u64 > msize {
                            dprintln!("[WARN] Skip {} because the size exceeds {} bytes", &new_path, &max_size.unwrap_or(0));
                            size_ok = false;
                        }
                    }
                    if size_ok {
                        match get(&sub_file, &new_path, destination_folder, fs, encrypt.as_ref(), ads, drive) {
                            Ok(saved) => {
                                local_visited_files.insert(path_check);
                                if saved {
                                    *success_files_count += 1;
                                }
                            }
                            Err(e) => dprintln!("{}", e.to_string()),
                        }
                    }
                }
            }
        }
    }

    Ok(local_visited_files)
}

/// Recursively process NTFS directories and files and apply glob matching
pub fn process_directory(
    fs: &mut BufReader<SectorReader<File>>,
    ntfs: &Ntfs,
    file: &NtfsFile<'_>,
    config_tree: &mut Node,
    current_path: &str,
    parent: &Entry,
    destination_folder: &str,
    visited_files: &mut HashSet<String>,
    drive: &str,
    success_files_count: &mut u32
) -> Result<u32> {
    let index = file.directory_index(fs)?;
    let mut iter = index.entries();
    let mut entries = Vec::new();
    let mut first_elements = config_tree.get_first_level_items();
    // Collect all entries into a vector
    while let Some(entry_result) = iter.next(fs) {
        match entry_result {
            Ok(entry) => {
                let name = entry
                    .key()
                    .unwrap()
                    .unwrap()
                    .name()
                    .to_string_lossy()
                    .to_string();
                let file_record_number = entry.file_reference().file_record_number();
                if name != "." {
                    entries.push(Entry {
                        name,
                        file_record_number,
                    });
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    for entry in &entries {
        let new_path = format!("{}/{}", current_path, entry.name);
        if let Ok(sub_file) = ntfs.file(fs, entry.file_record_number) {
            for (obj_name, obj_node) in &mut first_elements {
                if obj_node.all {
                    if !visited_files.contains(&current_path.to_string()) {
                        if let Ok(parent_obj) = ntfs.file(fs, parent.file_record_number) {
                            match process_all_directory (
                                fs,
                                ntfs,
                                &parent_obj,
                                obj_name.to_string(),
                                &current_path,
                                destination_folder,
                                drive,
                                obj_node.encrypt.clone(),
                                obj_node.max_size,
                                success_files_count
                                
                            ) {
                                Ok(current_visited_files) => {
                                    visited_files.extend(current_visited_files);
                                },
                                Err(e) => dprintln!("[ERROR] Problem to process the entire folder: {}", e.to_string()),
                            }
                        }
                    }
                } else {
                    let (obj_name_san, ads) = match obj_name.split_once(':') {
                        Some((left, right)) => {
                            let left_string = left.to_string(); 
                            (left_string, right) 
                        }
                        None => (obj_name.to_string(), ""), 
                    };
                    let mut path_check = new_path.clone();
                    if !(ads.is_empty() || ads == "") {
                        path_check = format!("{}:{}", path_check, ads);
                    }
                    if !visited_files.contains(&path_check)
                        && Pattern::new(&obj_name_san.as_str().to_lowercase())
                            .unwrap()
                            .matches(&new_path.as_str().to_lowercase())
                    {
                        if !&obj_name.contains("*") && !obj_node.all {
                            obj_node.checked = true;
                        }

                        if sub_file.is_directory() {
                            if let Err(e) = process_directory (
                                fs,
                                ntfs,
                                &sub_file,
                                obj_node,
                                &new_path,
                                entry,
                                destination_folder,
                                visited_files,
                                drive,
                                success_files_count
                            ){
                                dprintln!("[ERROR] Problem to process the folder {:?} {}", &sub_file, e.to_string());
                            }
                        }
                        let mut size_ok = true;
                        // check size
                        if let Some(msize) = obj_node.max_size {
                            if get_file_size(&sub_file, fs) as u64 > msize {
                                dprintln!("[WARN] Skip {} because the size exceeds {} bytes", &new_path, &obj_node.max_size.unwrap_or(0));
                                size_ok = false;
                            }
                        }

                        if size_ok && obj_node.children.is_empty() && !sub_file.is_directory() {
                            match get(
                                &sub_file,
                                &path_check,
                                destination_folder,
                                fs,
                                obj_node.encrypt.as_ref(),
                                ads,
                                drive,
                            ) {
                                Ok(saved) => {
                                    visited_files.insert(path_check);
                                    if saved {
                                        *success_files_count += 1;
                                    }
                                }
                                Err(e) => dprintln!("{}", e.to_string()),
                            }
                        }
                    }
                }
            }
        }

        if first_elements.iter().all(|(_, node)| node.checked) {
            break;
        }
    }

    Ok(*success_files_count)
}

fn get_file_size(file: &NtfsFile, mut fs:  &mut BufReader<SectorReader<File>>) -> u64 {
    let file_size = file.data(&mut fs, "").map_or(0, |data_item| {
        data_item.map_or(0, |d| d.to_attribute().map_or(0, |a| a.value_length()))
    });
    file_size 
}

pub fn get<T>(
    file: &NtfsFile,
    file_name: &str,
    out_dir: &str,
    fs: &mut T,
    encrypt: Option<&String>,
    ads: &str,
    drive: &str,
) -> Result<bool, Error>
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
    let is_ads = !(ads.is_empty() || ads == "");

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
            return Ok(false);
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "[ERROR] Failed to open file `{}` for writing: {}",
                output_file_name,
                e
            ));
        }
    };
    if !is_ads {
        // Iterate over attributes to find $INDEX_ALLOCATION
        let attributes: Vec<_> = file
            .attributes()
            .attach(fs)
            .collect::<Result<Vec<_>, _>>()?;
        for attribute in attributes {
            match attribute.to_attribute() {
                Ok(attr) => {
                    if attr.ty()? == NtfsAttributeType::IndexAllocation {
                        get_attr(&attr, fs, &output_file_name)?;
                    }
                }
                Err(_) => dprintln!("[ERROR] Can't getting attributes"),
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
            return Err(anyhow::anyhow!(
                "[WARN] The file {} does not have a $DATA attribute.",
                output_file_name
            ));
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

    // Get the valid data length
    let valid_data_length = get_valid_data_length(fs, &data_attribute)?;

    dprintln!(
        "[INFO] Saving {} bytes of data in `{}`",
        &valid_data_length,
        output_file_name
    );

    // Buffer for reading chunks of the file
    let mut read_buf = [0u8; 4096];

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
            let mut current_file_size: u64 = 0;
            // Stream data, encrypt each chunk, and write it to the file
            loop {
                match data_value.read(fs, &mut read_buf) {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            break;
                        }
                        if !data_attribute.is_resident() && !is_ads {
                            current_file_size += bytes_read as u64;
                            if current_file_size > valid_data_length {
                                // Write remaining data (including current read buffer) to a "slack" file
                                let mut slack_file = match OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(&format!("{}.FileSlack", output_file_name))
                                {
                                    Ok(f) => f,
                                    Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
                                        return Ok(false);
                                    }
                                    Err(e) => {
                                        return Err(anyhow::anyhow!(
                                            "[ERROR] Failed to open file `{}` for writing: {}",
                                            format!("{}.FileSlack", output_file_name),
                                            e
                                        ));
                                    }
                                };

                                // Write the remaining part of the current buffer to the slack file
                                let start_slack =
                                    (valid_data_length - (current_file_size - bytes_read as u64)) as usize;
                                slack_file.write_all(&read_buf[start_slack..bytes_read])?;

                                // padding with 0
                                let mut padding = vec![0; bytes_read - start_slack];
                                output_file.write_all(&padding)?;

                                // Continue reading and writing all remaining data to the slack file
                                while let Ok(slack_bytes_read) = data_value.read(fs, &mut read_buf) {
                                    if slack_bytes_read == 0 {
                                        break;
                                    }
                                    slack_file.write_all(&read_buf[..slack_bytes_read])?;

                                    padding = vec![0; slack_bytes_read];
                                    output_file.write_all(&padding)?;
                                }
                                break;
                            }
                        }

                        let chunk = if is_ads && read_buf.iter().all(|&b| b == 0) {
                            continue;
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
                    },
                    Err(err) => {
                        dprintln!("[ERROR] Reading data: {:?}", err);
                        break
                    }
                }
            }
        }
    } else {
        // No encryption, write the file normally in chunks
        if file_name == "/$Boot" {
            output_file.write_all(&get_boot(&drive).unwrap()).unwrap();
        } else {
            let mut current_file_size: u64 = 0;
            loop {
                match data_value.read(fs, &mut read_buf) {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            break;
                        }
                        if !data_attribute.is_resident() && !is_ads {
                            current_file_size += bytes_read as u64;
                            // Check if the Valid data is reached
                            if current_file_size > valid_data_length {
                                // Write remaining data (including current read buffer) to a "slack" file
                                let mut slack_file = match OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(&format!("{}.FileSlack", output_file_name))
                                {
                                    Ok(f) => f,
                                    Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
                                        return Ok(false);
                                    }
                                    Err(e) => {
                                        return Err(anyhow::anyhow!(
                                            "[ERROR] Failed to open file `{}` for writing: {}",
                                            format!("{}.FileSlack", output_file_name),
                                            e
                                        ));
                                    }
                                };

                                // Write the remaining part of the current buffer to the slack file
                                let start_slack =
                                    (valid_data_length - (current_file_size - bytes_read as u64)) as usize;
                                slack_file.write_all(&read_buf[start_slack..bytes_read])?;

                                // padding with 0
                                let mut padding = vec![0; bytes_read - start_slack];
                                output_file.write_all(&padding)?;

                                // Continue reading and writing all remaining data to the slack file
                                while let Ok(slack_bytes_read) = data_value.read(fs, &mut read_buf) {
                                    if slack_bytes_read == 0 {
                                        break;
                                    }
                                    slack_file.write_all(&read_buf[..slack_bytes_read])?;

                                    padding = vec![0; slack_bytes_read];
                                    output_file.write_all(&padding)?;
                                }
                                break;
                            }
                        }
                        let chunk = if is_ads && read_buf.iter().all(|&b| b == 0) {
                            continue;
                        } else {
                            &read_buf[..bytes_read]
                        };
                        if output_file.write_all(chunk).is_err() {
                            return Err(anyhow::anyhow!(
                                "[ERROR] Failed to write chunk to `{}`",
                                output_file_name
                            ));
                        }
                    },
                    Err(err) => {
                        dprintln!("[ERROR] Reading data: {:?}", err);
                        break
                    }
                }
            }
        }
    }
    // Retrieve timestamps from NtfsFile (replace these method calls with the actual methods from NtfsFile)
    if let Ok(file_std_info) = file.info() {
        let modified_time: DateTime<Local> =
            nt_timestamp_to_datetime(file_std_info.modification_time().nt_timestamp());

        let modified_file_time = FileTime::from_system_time(add_timezone_offset_to_system_time(
            modified_time.into(),
            modified_time.offset().local_minus_utc().into(),
        ));

        set_file_handle_times(&output_file, None, Some(modified_file_time))
            .map_err(|e| anyhow::anyhow!("[ERROR] Failed to set file timestamps: {}", e))?;
    }
    match output_file.flush() {
        Ok(_) => {
            dprintln!("[INFO] Data successfully saved to `{}`", output_file_name);
            return Ok(true);
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

fn get_valid_data_length<T>(fs: &mut T, attribut: &NtfsAttribute) -> Result<u64, Error>
where
    T: Read + Seek,
{
    return match &attribut.ty()? {
        NtfsAttributeType::Data => match attribut.position().value() {
            Some(data_attr_position) => {
                let mut buff = vec![0u8; 64];
                fs.seek(SeekFrom::Start(data_attr_position.get()))?;
                fs.read_exact(&mut buff)?;
                let byte_57 = buff[56];
                let byte_58 = buff[57];
                let byte_59 = buff[58];
                let byte_60 = buff[59];
                let vdl = ((byte_60 as u64) << 24)
                    | ((byte_59 as u64) << 16)
                    | ((byte_58 as u64) << 8)
                    | (byte_57 as u64);
                Ok(vdl)
            }
            None => Err(anyhow::anyhow!("[ERROR] $DATA position not found")),
        },
        _ => Err(anyhow::anyhow!("[ERROR] Wrong attribut type")),
    };
}

fn get_attr<T>(attr: &NtfsAttribute, fs: &mut T, output_file_name: &str) -> Result<(), Error>
where
    T: Read + Seek,
{
    let attr_name = attr.name()?.to_string_lossy().to_string();
    dprintln!(
        "[INFO] Found $INDEX_ALLOCATION attribute : `{}`",
        &attr_name
    );

    let attr_path = format!("{}%3A{}.idx", output_file_name, &attr_name);
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

fn nt_timestamp_to_datetime(nt_timestamp: u64) -> DateTime<Local> {
    let system_time = nt_timestamp_to_system_time(nt_timestamp);
    DateTime::<Local>::from(system_time)
}

fn add_timezone_offset_to_system_time(system_time: SystemTime, offset_seconds: i64) -> SystemTime {
    if offset_seconds >= 0 {
        system_time + Duration::from_secs(offset_seconds as u64)
    } else {
        system_time - Duration::from_secs((-offset_seconds) as u64)
    }
}

fn get_boot(drive: &str) -> Result<Vec<u8>, Error> {
    let drive_path = if cfg!(target_os = "windows") {
        format!("{}:\\", drive)
    } else {
        drive.to_string()
    };
    let drive_path_ext = if cfg!(target_os = "windows") {
        format!("\\\\.\\{}:", drive)
    } else {
        drive.to_string()
    };

    // Check if the drive exists before attempting to open it
    if Path::new(&drive_path).exists() {
        let mut file = File::open(&drive_path_ext).unwrap();
        let mut boot_sector = vec![0u8; 8192];

        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut boot_sector)?;

        return Ok(boot_sector);
    }

    Err(anyhow::anyhow!(
        "[ERROR] Drive {} does not exist",
        drive_path
    ))
}