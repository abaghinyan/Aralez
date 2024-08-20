//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::command_info::CommandInfo;
use crate::config::SearchConfig;
use crate::utils::{get, get_file_name};
use anyhow::Result;
use ntfs::{Ntfs};
use std::io::{Read, Seek};
use ntfs::indexes::NtfsFileNameIndex;
use std::collections::HashSet;

pub fn initialize_ntfs<T: Read + Seek>(fs: &mut T) -> Result<Ntfs> {
    let mut ntfs = Ntfs::new(fs)?;
    ntfs.read_upcase_table(fs)?;
    Ok(ntfs)
}

pub fn initialize_command_info<'n, T: Read + Seek>(fs: T, ntfs: &'n Ntfs) -> Result<CommandInfo<'n, T>> {
    Ok(CommandInfo::new(fs, ntfs)?)
}

/// Navigate to the Logs directory and find all files.
pub fn find_files_in_dir<T>(info: &mut CommandInfo<T>, element: &SearchConfig, out_dir: &str) -> Result<()>
where
    T: Read + Seek,
{
    // Navigate to the Logs directory
    navigate_to_directory(info, &element.dir_path)?;

    // List all files in the Logs directory
    list_files_in_current_dir(info, element, out_dir)
}

/// Navigate to a directory based on a path of components.
fn navigate_to_directory<T>(info: &mut CommandInfo<T>, dir_path: &str) -> Result<()>
where
    T: Read + Seek,
{
    let path_components: Vec<&str> = dir_path.split('\\').collect();

    // Reset the current dir to root
    info.current_directory = vec![info.ntfs.root_directory(&mut info.fs)?];
    
    for component in &path_components {
        let current_directory = info.current_directory.last().unwrap();
        let index = current_directory.directory_index(&mut info.fs)?;
        let mut finder = index.finder();
        if let Some(entry) = NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, component) {
            let entry = entry?;
            let file = entry.to_file(info.ntfs, &mut info.fs)?;
    
            if file.is_directory() {
                info.current_directory.push(file);
            } else {
                dprintln!("Expected {} to be a directory in {:?}", component, &dir_path);
            }
        } else {
            dprintln!("Directory {} not found in {:?}", component, &dir_path);
        }
    }
    Ok(())
}

fn list_files_in_current_dir<T>(info: &mut CommandInfo<T>, config: &SearchConfig, out_dir: &str) -> Result<()>
where
    T: Read + Seek,
{
    let mut directories_to_recurse = Vec::new();
    let current_directory = info.current_directory.last().unwrap();
    let index = current_directory.directory_index(&mut info.fs)?;

    let mut entries = index.entries();
    let mut seen_files = HashSet::new();

    while let Some(entry_result) = entries.next(&mut info.fs) {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_e) => {
                dprintln!("Error reading entry: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        let file = match entry.to_file(info.ntfs, &mut info.fs) {
            Ok(file) => file,
            Err(_e) => {
                dprintln!("Error converting entry to file: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        // Get the file size
        let file_size = match file.data(&mut info.fs, "") {
            Some(data_item) => {
                let data_item = data_item?;  // Bind the data item to a variable to extend its lifetime
                let data_attribute = data_item.to_attribute()?;  // Now, this will live long enough
                data_attribute.value_length()  // Size of the data stream
            },
            None => 0, // In case there is no data attribute, treat the size as 0
        };

        match get_file_name(&file, &mut info.fs) {
            Ok(file_name) => {
                if let Some(ref extensions) = config.extensions {
                    if extensions.contains(&".*".to_string()) && !file.is_directory() {
                        if seen_files.insert(file_name.clone()) && config.max_size.map_or(true, |max| file_size <= max) {
                            dprintln!("Found file: {}", file_name);
                            get(&file, &file_name, out_dir, &mut info.fs, config.encrypt.as_ref())?;
                        }
                    } else if extensions.contains(&"".to_string()) {
                        if seen_files.insert(file_name.clone()) {
                            if file.is_directory() {
                                dprintln!("Found directory: {}", file_name);
                                let dir_path = format!("{}/{}", out_dir, file_name);
                                std::fs::create_dir_all(&dir_path)?;
                                directories_to_recurse.push((file, dir_path));
                            } else if config.max_size.map_or(true, |max| file_size <= max) {
                                dprintln!("Found file: {}", file_name);
                                get(&file, &file_name, out_dir, &mut info.fs, config.encrypt.as_ref())?;
                            }
                        }
                    } else {
                        for ext in extensions {
                            if !file.is_directory() && file_name.ends_with(ext) && seen_files.insert(file_name.clone()) {
                                if config.max_size.map_or(true, |max| file_size <= max) {
                                    dprintln!("Found file: {}", file_name);
                                    get(&file, &file_name, out_dir, &mut info.fs, config.encrypt.as_ref())?;
                                }
                                break;
                            }
                        }
                    }
                } else {
                    // Handle the case where no extensions are specified
                    if !file.is_directory() && seen_files.insert(file_name.clone()) {
                        if config.max_size.map_or(true, |max| file_size <= max) {
                            dprintln!("Found file: {}", file_name);
                            get(&file, &file_name, out_dir, &mut info.fs, config.encrypt.as_ref())?;
                        }
                    }
                }
            }
            Err(_e) => {
                dprintln!("Error getting file name: {:?}", _e);
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

/// List all files in the current directory.
pub fn get_users<T>(info: &mut CommandInfo<T>) -> Result<Vec<String>>
where
    T: Read + Seek,
{
    let mut users = Vec::new();
    let dir_path = "Users";
    // Navigate to the Logs directory
    navigate_to_directory(info, &dir_path)?;
    let current_directory = info.current_directory.last().unwrap();
    let index = current_directory.directory_index(&mut info.fs)?;
    let mut entries = index.entries();
    let mut seen_files = HashSet::new();

    while let Some(entry_result) = entries.next(&mut info.fs) {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_e) => {
                dprintln!("Error reading entry: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        let file = match entry.to_file(info.ntfs, &mut info.fs) {
            Ok(file) => file,
            Err(_e) => {
                dprintln!("Error converting entry to file: {:?}", _e);
                continue; // Skip to the next entry if there is an error
            }
        };

        if file.is_directory() {
            match get_file_name(&file, &mut info.fs) {
                Ok(file_name) => {
                    // TODO: Try to find another solution for duplicate files
                    if seen_files.insert(file_name.clone()){
                        users.push(file_name.to_string());
                    }
                }
                Err(_e) => {
                    continue; // Skip to the next entry if there is an error
                }
            }
        }
    }

    Ok(users)
}

