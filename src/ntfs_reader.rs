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
    ensure_directory_exists, get, get_level_path_pattern, get_level_path_regex, get_object_name, get_subfolder_level, get_subfolder_level_regex
};
use anyhow::Result;
use glob::Pattern;
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::Ntfs;
use ntfs::NtfsFile;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::io::BufReader;

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
    out_dir: &str,
) -> Result<()>
where
    T: Read + Seek,
{
    // Navigate to the Logs directory
    let dir_path = &element.get_expanded_dir_path();
    match navigate_to_directory(info, &dir_path) {
        Ok(_) => {
            // List all files in the Logs directory
            let mut visited_files: HashSet<String> = HashSet::new();
            let mut visited_dirs = HashSet::new();
            return match &element.r#type {
                Some(el_type) => match el_type {
                    TypeConfig::String => list_files_in_current_dir(info, element, out_dir),
                    TypeConfig::Glob => list_files_in_current_dir_glob(
                        info,
                        element,
                        out_dir,
                        String::new(),
                        &mut visited_files,
                        &mut visited_dirs,
                    ),
                    TypeConfig::Regex => {
                        list_files_in_current_dir_regex(info, element, out_dir, String::new())
                    }
                },
                None => list_files_in_current_dir_glob(
                    info,
                    element,
                    out_dir,
                    String::new(),
                    &mut visited_files,
                    &mut visited_dirs,
                ),
            };
        }
        Err(e) => dprintln!("{}", e),
    }

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

pub fn list_files_in_current_dir<T>(
    info: &mut CommandInfo<T>,
    config: &SearchConfig,
    out_dir: &str,
) -> Result<()>
where
    T: Read + Seek,
{
    let mut directories_to_recurse = Vec::new();
    let current_directory = info.current_directory.last().unwrap();
    let index = current_directory.directory_index(&mut info.fs)?;

    let mut entries = index.entries();
    let mut visited_files = HashSet::new();

    while let Some(entry_result) = entries.next(&mut info.fs) {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_e) => {
                dprintln!("[ERROR] Error reading entry: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        let file = match entry.to_file(info.ntfs, &mut info.fs) {
            Ok(file) => file,
            Err(_e) => {
                dprintln!("[ERROR] Error converting entry to file: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        // Get the file size
        let file_size = match file.data(&mut info.fs, "") {
            Some(data_item) => {
                let data_item = data_item?; // Bind the data item to a variable to extend its lifetime
                let data_attribute = data_item.to_attribute()?; // Now, this will live long enough
                data_attribute.value_length() // Size of the data stream
            }
            None => 0, // In case there is no data attribute, treat the size as 0
        };

        match get_object_name(&file, &mut info.fs) {
            Ok(file_name) => {
                if let Some(ref objects) = config.objects {
                    if objects.contains(&".*".to_string()) && !file.is_directory() {
                        if visited_files.insert(file_name.clone())
                            && config.max_size.map_or(true, |max| file_size <= max)
                        {
                            dprintln!("[INFO] Found file: {}", file_name);
                            get(
                                &file,
                                &file_name,
                                out_dir,
                                &mut info.fs,
                                config.encrypt.as_ref(),
                            );
                        }
                    } else if objects.contains(&"".to_string()) {
                        if visited_files.insert(file_name.clone()) {
                            if file.is_directory() {
                                dprintln!("[INFO] Found directory: {}", file_name);
                                let dir_path = format!("{}/{}", out_dir, file_name);
                                std::fs::create_dir_all(&dir_path)?;
                                directories_to_recurse.push((file, dir_path));
                            } else if config.max_size.map_or(true, |max| file_size <= max) {
                                dprintln!("[INFO] Found file: {}", file_name);
                                get(
                                    &file,
                                    &file_name,
                                    out_dir,
                                    &mut info.fs,
                                    config.encrypt.as_ref(),
                                );
                            }
                        }
                    } else {
                        for ext in objects {
                            if !file.is_directory()
                                && file_name.ends_with(ext)
                                && visited_files.insert(file_name.clone())
                            {
                                if config.max_size.map_or(true, |max| file_size <= max) {
                                    dprintln!("[INFO] Found file: {}", file_name);
                                    get(
                                        &file,
                                        &file_name,
                                        out_dir,
                                        &mut info.fs,
                                        config.encrypt.as_ref(),
                                    );
                                }
                                break;
                            }
                        }
                    }
                } else {
                    // Handle the case where no objects are specified
                    if !file.is_directory() && visited_files.insert(file_name.clone()) {
                        if config.max_size.map_or(true, |max| file_size <= max) {
                            dprintln!("[INFO] Found file: {}", file_name);
                            get(
                                &file,
                                &file_name,
                                out_dir,
                                &mut info.fs,
                                config.encrypt.as_ref(),
                            );
                        }
                    }
                }
            }
            Err(_e) => {
                dprintln!("[ERROR] Error getting file name: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        }
    }

    // Process directories after the current entries are done
    for (directory, path) in directories_to_recurse {
        info.current_directory.push(directory);
        list_files_in_current_dir(info, config, &path)?;
        info.current_directory.pop();
    }

    Ok(())
}

pub fn list_files_in_current_dir_regex<T>(
    info: &mut CommandInfo<T>,
    config: &SearchConfig,
    out_dir: &str,
    relative_path: String,
) -> Result<()>
where
    T: Read + Seek,
{
    let mut directories_to_recurse = Vec::new();
    let current_directory = info.current_directory.last().unwrap();
    let index = current_directory.directory_index(&mut info.fs)?;

    let mut entries = index.entries();
    let mut visited_files = HashSet::new();

    let (folder_patterns, file_patterns): (Option<Vec<Regex>>, Option<Vec<Regex>>) = config
        .objects
        .as_ref()
        .map(|patterns| {
            let mut folder_patterns = Vec::new();
            let mut file_patterns = Vec::new();
            for pattern in patterns {
                if let Some(last_sep) = pattern.rfind("\\\\") {
                    let folder_part = &format!("^{}$", &pattern[..last_sep]); // Folder path before the last `\`
                    let file_part = &pattern[last_sep + 2..]; // File part after the last `\`
                    file_patterns.push(Regex::new(&file_part).unwrap());
                    folder_patterns.push(Regex::new(&folder_part).unwrap());
                } else {
                    file_patterns.push(Regex::new(&pattern).unwrap());
                }
            }
            (Some(folder_patterns), Some(file_patterns))
        })
        .unwrap_or((None, None));
    while let Some(entry_result) = entries.next(&mut info.fs) {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_e) => {
                dprintln!("[ERROR] Error reading entry: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        let file: ntfs::NtfsFile<'_> = match entry.to_file(info.ntfs, &mut info.fs) {
            Ok(file) => file,
            Err(_e) => {
                dprintln!("[ERROR] Error converting entry to file: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        // Get the file size
        let file_size = match file.data(&mut info.fs, "") {
            Some(data_item) => {
                let data_item = data_item?; // Bind the data item to a variable to extend its lifetime
                let data_attribute = data_item.to_attribute()?; // Now, this will live long enough
                data_attribute.value_length() // Size of the data stream
            }
            None => 0, // In case there is no data attribute, treat the size as 0
        };
        match get_object_name(&file, &mut info.fs) {
            Ok(object_name) => {
                // Check if the current file or directory matches any of the regex patterns
                if file.is_directory() {
                    let mut reg_data = object_name.clone();
                    if !relative_path.is_empty() {
                        reg_data = format!("{}\\{}", relative_path, object_name.clone());
                    }
                    let level = get_subfolder_level_regex(&reg_data);
                    let matches_pattern = folder_patterns.as_ref().map_or(true, |patterns| {
                        patterns.iter().any(|regex| {
                            Regex::new(&get_level_path_regex(regex.as_str(), level).unwrap())
                                .expect("Regex problem")
                                .is_match(&reg_data)
                        })
                    });
                    if matches_pattern {
                        let folder_output_path = format!("{}\\{}", out_dir, object_name);
                        directories_to_recurse.push((file, folder_output_path, reg_data));
                    }
                } else {
                    let matches_pattern = file_patterns.as_ref().map_or(true, |patterns| {
                        patterns.iter().any(|regex| regex.is_match(&object_name))
                    });
                    if matches_pattern {
                        let matches_folder_pattern =
                            folder_patterns.as_ref().map_or(true, |patterns| {
                                patterns.iter().any(|regex| regex.is_match(&relative_path))
                            });
                        // Keep `visited_files` logic untouched

                        if (matches_folder_pattern
                            || (relative_path.is_empty()
                                && folder_patterns.as_ref().unwrap().len() == 0))
                            && visited_files.insert(object_name.clone())
                        {
                            // Respect the original file size limit
                            if config.max_size.map_or(true, |max| file_size <= max) {
                                dprintln!("[INFO] Found file: {}", object_name);
                                get(
                                    &file,
                                    &object_name,
                                    out_dir,
                                    &mut info.fs,
                                    config.encrypt.as_ref(),
                                );
                            }
                        }
                    }
                }
            }
            Err(_e) => {
                dprintln!("[ERROR] Error getting file name: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        }
    }

    // Process directories after the current entries are done
    for (directory, path, relative_path) in directories_to_recurse {
        info.current_directory.push(directory);
        list_files_in_current_dir_regex(info, config, &path, relative_path)?;
        info.current_directory.pop();
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
    visited_dirs: &mut HashSet<String>, // Keep track of visited directories
) -> Result<()>
where
    T: Read + Seek,
{
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

        let file_size = file.data(&mut info.fs, "").map_or(0, |data_item| {
            data_item.map_or(0, |d| d.to_attribute().map_or(0, |a| a.value_length()))
        });

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
                            list_files_in_current_dir_glob(
                                info,
                                config,
                                &folder_output_path,
                                reg_data.clone(),
                                visited_files,
                                visited_dirs, // Pass visited dirs to prevent loops
                            )?;
                        } else {
                            let level = get_subfolder_level(&reg_data);

                            if let Some(subpath) = get_level_path_pattern(folder_pattern, level) {
                                if Pattern::new(&subpath)
                                    .expect("Failed to read glob pattern")
                                    .matches(&reg_data)
                                    || subpath.ends_with("**")
                                {
                                    let folder_output_path = format!("{}/{}", out_dir, object_name);
                                    info.current_directory.push(file.clone());
                                    list_files_in_current_dir_glob(
                                        info,
                                        config,
                                        &folder_output_path,
                                        reg_data.clone(),
                                        visited_files,
                                        visited_dirs, // Pass visited dirs to prevent loops
                                    )?;
                                }
                            }
                        }
                    }
                } else {
                    // Process files
                    for (folder_pattern, file_pattern) in &folder_file_pairs {
                        if !file_pattern.is_empty() {
                            let rel_path = if !relative_path.is_empty() {
                                format!("{}/{}", relative_path, object_name)
                            } else {
                                object_name.clone()
                            };
                            let full_pattern = if folder_pattern.is_empty() {
                                file_pattern.to_string()
                            } else {
                                format!("{}/{}", folder_pattern, file_pattern)
                            };
                            // Manage the case **\\*, if folder_pattern and rel_path are on the same level
                            if folder_pattern.ends_with("**") && file_pattern != "**" {
                                let level_rel_path = get_subfolder_level(&rel_path);
                                let level_folder_pattern = get_subfolder_level(&folder_pattern);
                                if level_rel_path <= level_folder_pattern {
                                    break;
                                }
                            } 

                            if Pattern::new(&full_pattern.replace("\\", "/"))
                                .expect("Failed to read glob pattern")
                                .matches(&rel_path)
                                && !visited_files.contains(&rel_path)
                            {
                                if config.max_size.map_or(true, |max| file_size <= max) {
                                    dprintln!("[INFO] Found file: {}", object_name);
                                    get(
                                        &file,
                                        &object_name,
                                        out_dir,
                                        &mut info.fs,
                                        config.encrypt.as_ref(),
                                    );
                                    visited_files.insert(rel_path.clone());
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

    Ok(())
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
    
    config.sanitize().expect("[ERROR] Config sanitization failed");
    let drive = format!("{}\\{}", root_output.to_string(), drive);
    find_files_in_dir(
        info,
        config,
        &format!("{}\\{}", drive, &config.get_expanded_dir_path()),
    )
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
                dprintln!("[INFO] Running {}", path_key);  // Replaced the progress bar message with dprintln!
                search_in_config(&mut info, &mut artifact, root_output, drive_letter.to_string())?;
                processed_paths.insert(path_key);
            }
        }
    }

    Ok(())
}

/// Process all NTFS drives except the C drive
pub fn process_all_drives(
    section_config: &mut SectionConfig,
    root_output: &str,
) -> Result<()> {
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