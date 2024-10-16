//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::command_info::CommandInfo;
use crate::config::{SearchConfig, SectionConfig, TypeConfig};
use crate::sector_reader::SectorReader;
use crate::utils::{
    ensure_directory_exists, get, get_level_path_pattern, get_object_name, get_subfolder_level,
};
use anyhow::Result;
use glob::Pattern;
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::Ntfs;
use ntfs::NtfsFile;
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";

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

/// Function to check if a partition is NTFS by looking for the NTFS signature
fn is_ntfs_partition<T: Read + Seek>(reader: &mut T) -> io::Result<bool> {
    let mut boot_sector = [0u8; 512]; // Boot sector is typically 512 bytes

    // Seek to the start of the partition and read the first 512 bytes (the boot sector)
    reader.seek(SeekFrom::Start(0))?;
    match reader.read_exact(&mut boot_sector) {
        Ok(_) => return Ok(&boot_sector[3..11] == NTFS_SIGNATURE),
        Err(_) => return Ok(false),
    };
}

pub fn initialize_ntfs<T: Read + Seek>(fs: &mut T) -> Result<Ntfs> {
    let mut ntfs = Ntfs::new(fs)?;
    ntfs.read_upcase_table(fs)?;
    Ok(ntfs)
}

pub fn initialize_command_info<'n, T: Read + Seek>(
    fs: T,
    ntfs: &'n Ntfs,
) -> Result<CommandInfo<'n, T>> {
    Ok(CommandInfo::new(fs, ntfs)?)
}

/// Navigate to the Logs directory and find all files.
pub fn find_files_in_dir<T>(
    info: &mut CommandInfo<T>,
    element: &mut SearchConfig,
    root_output: &str,
    drive: &str,
) -> Result<()>
where
    T: Read + Seek,
{
    let root_path = format!("{}\\{}", root_output.to_string(), drive);
    // Navigate to the Logs directory
    let dir_path = &element.get_expanded_dir_path();
    let mut success_files_count: u32 = 0;

    match navigate_to_directory(info, &dir_path) {
        Ok(_) => {
            // List all files in the Logs directory
            let mut visited_files: HashSet<String> = HashSet::new();
            let mut visited_dirs = HashSet::new();
            let out_dir = &format!("{}\\{}", root_path, &element.get_expanded_dir_path());

            match &element.r#type {
                Some(el_type) => match el_type {
                    TypeConfig::Glob => {
                        match list_files_in_current_dir_glob(
                            info,
                            element,
                            out_dir,
                            String::new(),
                            &mut visited_files,
                            &mut visited_dirs,
                            drive,
                        ) {
                            Ok(count) => success_files_count += count,
                            Err(e) => dprintln!("{:?}", e),
                        };
                    }
                },
                None => {
                    match list_files_in_current_dir_glob(
                        info,
                        element,
                        out_dir,
                        String::new(),
                        &mut visited_files,
                        &mut visited_dirs,
                        drive,
                    ) {
                        Ok(count) => success_files_count += count,
                        Err(e) => dprintln!("{:?}", e),
                    };
                }
            };
        }
        Err(e) => dprintln!("{}", e),
    }

    dprintln!(
        "[INFO] Collection completed for {} with {} collected files",
        dir_path,
        success_files_count
    );

    Ok(())
}

/// Navigate to a directory based on a path of components.
fn navigate_to_directory<T>(info: &mut CommandInfo<T>, dir_path: &str) -> Result<(), anyhow::Error>
where
    T: Read + Seek,
{
    let path_components: Vec<&str> = dir_path.split("\\").collect();

    // Reset the current dir to root
    info.current_directory = vec![info.ntfs.root_directory(&mut info.fs)?];
    for component in &path_components {
        let current_directory = info.current_directory.last().unwrap();
        let index = current_directory.directory_index(&mut info.fs)?;
        let mut finder = index.finder();
        if let Some(entry) =
            NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, component)
        {
            let entry = entry?;
            let file = entry.to_file(info.ntfs, &mut info.fs)?;

            if file.is_directory() {
                info.current_directory.push(file);
            } else {
                return Err(anyhow::anyhow!(format!(
                    "[ERROR] Expected {} to be a directory in {:?}",
                    component, &dir_path
                )));
            }
        } else {
            return Err(anyhow::anyhow!(format!(
                "[WARN] Directory {} not found in {:?}",
                component, dir_path
            )));
        }
    }
    Ok(())
}

/// **      : files of current folder and subfolders
/// **\\*   : files of subfolders
/// *       : files of current folder   
pub fn list_files_in_current_dir_glob<T>(
    info: &mut CommandInfo<T>,
    config: &SearchConfig,
    out_dir: &str,
    relative_path: String,
    visited_files: &mut HashSet<String>,
    visited_dirs: &mut HashSet<String>,
    drive: &str,
) -> Result<u32>
where
    T: Read + Seek,
{
    let mut success_files_count: u32 = 0;

    let current_directory: &NtfsFile<'_> = &info.current_directory.last().unwrap().clone();
    let index = current_directory.directory_index(&mut info.fs)?;
    let mut entries = index.entries();

    // Extract folder and file pattern pairs from the configuration
    let folder_file_pairs = config
        .objects
        .as_ref()
        .map(|patterns| {
            let mut folder_file_pairs = Vec::new();
            for pattern in patterns {
                if pattern.ends_with("**") {
                    let folder_part = pattern;
                    let file_part = "**";
                    folder_file_pairs.push((folder_part.to_string(), file_part.to_string()));
                } else {
                    let sanitized_pattern = pattern.replace("\\", "/");
                    if let Some(last_sep) = sanitized_pattern.rfind("/") {
                        let folder_part = &sanitized_pattern[..last_sep];
                        let file_part = &sanitized_pattern[last_sep + 1..];
                        folder_file_pairs.push((folder_part.to_string(), file_part.to_string()));
                    } else {
                        folder_file_pairs.push((String::new(), sanitized_pattern.clone()));
                    }
                }
            }
            folder_file_pairs
        })
        .unwrap_or_default(); // In case there are no patterns, return an empty Vec
    while let Some(entry_result) = entries.next(&mut info.fs) {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(e) => {
                dprintln!("[ERROR] Error reading entry: {:?}", e);
                continue;
            }
        };

        let file = match entry.to_file(info.ntfs, &mut info.fs) {
            Ok(file) => file,
            Err(e) => {
                dprintln!("[ERROR] Error converting entry to file: {:?}", e);
                continue;
            }
        };

        let file_size = file.allocated_size();

        match get_object_name(&file, &mut info.fs) {
            Ok(object_name) => {
                let full_path = format!("{}/{}", relative_path, object_name);

                // Prevent directory loop by checking if this directory has been visited before
                if file.is_directory() {
                    if visited_dirs.contains(&full_path) {
                        continue;
                    }
                    visited_dirs.insert(full_path.clone()); // Mark directory as visited

                    // Proceed with directory traversal logic
                    let reg_data = if !relative_path.is_empty() {
                        format!("{}/{}", relative_path, object_name)
                    } else {
                        object_name.clone()
                    };
                    for (folder_pattern, _) in &folder_file_pairs {
                        if folder_pattern.starts_with("**/") {
                            let folder_output_path = format!("{}/{}", out_dir, object_name);
                            info.current_directory.push(file.clone());
                            match list_files_in_current_dir_glob(
                                info,
                                config,
                                &folder_output_path,
                                reg_data.clone(),
                                visited_files,
                                visited_dirs,
                                drive,
                            ) {
                                Ok(count) => success_files_count += count,
                                Err(e) => dprintln!("{:?}", e),
                            };
                        } else {
                            let level = get_subfolder_level(&reg_data);

                            if let Some(subpath) = get_level_path_pattern(folder_pattern, level) {
                                if Pattern::new(&subpath.to_lowercase())
                                    .expect("Failed to read glob pattern")
                                    .matches(&reg_data.to_lowercase())
                                    || subpath.ends_with("**")
                                {
                                    let folder_output_path = format!("{}/{}", out_dir, object_name);
                                    info.current_directory.push(file.clone());
                                    match list_files_in_current_dir_glob(
                                        info,
                                        config,
                                        &folder_output_path,
                                        reg_data.clone(),
                                        visited_files,
                                        visited_dirs,
                                        drive,
                                    ) {
                                        Ok(count) => success_files_count += count,
                                        Err(e) => dprintln!("{:?}", e),
                                    };
                                }
                            }
                        }
                    }
                } else {
                    // Process files
                    for (folder_pattern, file_pattern) in &folder_file_pairs {
                        if !file_pattern.is_empty() {
                            let mut rel_path = if !relative_path.is_empty() {
                                format!("{}/{}", relative_path, object_name)
                            } else {
                                object_name.clone()
                            };
                            let (file_pattern, ads) = match file_pattern.split_once(':') {
                                Some((left, right)) => {
                                    let left_string = left.to_string(); // Create a variable for the `String`
                                    (left_string, right) // Return the `String` itself, not a reference to it
                                },
                                None => (file_pattern.to_string(), ""), // Ensure consistency with String type
                            };
                            
                            let full_pattern = if folder_pattern.is_empty() {
                                file_pattern.clone() // Clone the file_pattern to prevent the move
                            } else {
                                format!("{}/{}", folder_pattern, file_pattern.clone()) // Clone here as well
                            };                        

                            if folder_pattern.ends_with("**") && file_pattern != "**" {
                                let level_rel_path = get_subfolder_level(&rel_path);
                                let level_folder_pattern = get_subfolder_level(&folder_pattern);
                                if level_rel_path <= level_folder_pattern {
                                    break;
                                }
                            }

                            if Pattern::new(&full_pattern.replace("\\", "/").to_lowercase())
                                .expect("Failed to read glob pattern")
                                .matches(&rel_path.to_lowercase())
                            {
                                if ads != "" {
                                    rel_path.push_str(&format!(":{}", ads));
                                }
                                if !visited_files.contains(&rel_path) {
                                    if config
                                        .max_size
                                        .map_or(true, |max| u64::from(file_size) <= max)
                                    {
                                        dprintln!("[INFO] Found file: {}", rel_path);

                                        match get(
                                            &file,
                                            &object_name,
                                            out_dir,
                                            &mut info.fs,
                                            config.encrypt.as_ref(),
                                            ads,
                                            drive,
                                        ) {
                                            Ok(_) => success_files_count += 1,
                                            Err(e) => dprintln!("{}", e.to_string()),
                                        }
                                        visited_files.insert(rel_path.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                dprintln!("[ERROR] Error getting file name: {:?}", e);
                continue;
            }
        }
    }

    Ok(success_files_count)
}

fn search_in_config<T>(
    info: &mut CommandInfo<T>,
    config: &mut SearchConfig,
    root_output: &str,
    drive: String,
) -> Result<()>
where
    T: Read + Seek,
{
    config
        .sanitize()
        .expect("[ERROR] Config sanitization failed");

    find_files_in_dir(info, config, root_output, &drive)
}

pub fn process_drive_artifacts(
    drive: &str,
    section_config: &mut SectionConfig,
    root_output: &str,
) -> Result<()> {
    let drive_letter = drive.chars().next().unwrap();
    let output_path = format!("{}\\{}", root_output, drive_letter);

    ensure_directory_exists(&output_path)?;

    let f = File::open(format!("\\\\.\\{}:", drive_letter))?;
    let sr = SectorReader::new(f, 4096)?;
    let mut fs = BufReader::new(sr);
    let ntfs = initialize_ntfs(&mut fs)?;

    let mut info = initialize_command_info(fs, &ntfs)?;
    let mut processed_paths = HashSet::new();

    for (_, artifacts) in &mut section_config.entries {
        for mut artifact in artifacts {
            let path_key = format!(
                "{}\\{:?}",
                artifact.get_expanded_dir_path(),
                artifact.objects.clone().unwrap_or_default()
            );
            if !processed_paths.contains(&path_key) {
                dprintln!("[INFO] Collecting {}", path_key);
                search_in_config(
                    &mut info,
                    &mut artifact,
                    root_output,
                    drive_letter.to_string(),
                )?;
                processed_paths.insert(path_key);
            }
        }
    }

    Ok(())
}

/// Process all NTFS drives except the C drive
pub fn process_all_drives(section_config: &mut SectionConfig, root_output: &str) -> Result<()> {
    let ntfs_drives = list_ntfs_drives()?;

    'for_drive: for drive in ntfs_drives {
        if let Some(iter_drives) = &section_config.exclude_drives {
            for iter_drive in iter_drives {
                if drive.starts_with(iter_drive) {
                    continue 'for_drive;
                }
            }
        }
        process_drive_artifacts(&drive, section_config, root_output)?;
    }

    Ok(())
}
