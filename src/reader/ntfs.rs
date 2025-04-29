#[cfg(target_os = "windows")]
pub mod windows_os {
    pub use crate::utils::ensure_directory_exists;

    pub use std::io;
    pub use std::path::Path;
    pub use std::io::SeekFrom;
}

#[cfg(target_os = "windows")]
use windows_os::*;

use crate::config::SectionConfig;
use crate::reader::sector::SectorReader;
use crate::utils::get;
use ntfs::{Ntfs, NtfsFile};
use anyhow::Result;
use glob::Pattern;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::u64;

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