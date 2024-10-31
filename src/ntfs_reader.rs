//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::config::SectionConfig;
use crate::sector_reader::SectorReader;
use crate::utils::{
    ensure_directory_exists, get, split_path,
};
use anyhow::Result;
use glob::Pattern;
use ntfs::Ntfs;
use ntfs::NtfsFile;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";

#[derive(Debug)]
struct Entry {
    name: String,
    file_record_number: u64,
}

fn process_all_directory(
    fs: &mut BufReader<SectorReader<File>>,
    ntfs: &Ntfs,
    file: &NtfsFile<'_>,
    obj_name: String,
    current_path: &str,
    destination_folder: &str,
    drive: &str,
    encrypt: Option<String>
) -> Result<(HashSet<String>, u32)> {
    let index = file.directory_index(fs)?;
    let mut iter = index.entries();
    let mut entries = Vec::new();
    let mut success_files_count: u32 = 0;
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
                    encrypt.clone()
                ) {
                    dprintln!("Error processing subdirectory: {:?}", e);
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
                    match get(&sub_file, &new_path, destination_folder, fs, encrypt.as_ref(), ads, drive) {
                        Ok(_) => {
                            local_visited_files.insert(path_check);
                            success_files_count += 1
                        }
                        Err(e) => dprintln!("[ERROR] {}", e.to_string()),
                    }
                }
            }
        }
    }

    Ok((local_visited_files, success_files_count))
}

/// Recursively process NTFS directories and files and apply glob matching
fn process_directory(
    fs: &mut BufReader<SectorReader<File>>,
    ntfs: &Ntfs,
    file: &NtfsFile<'_>,
    config_tree: &mut Node,
    current_path: &str,
    parent: &Entry,
    destination_folder: &str,
    visited_files: &mut HashSet<String>,
    drive: &str
) -> Result<u32> {
    let index = file.directory_index(fs)?;
    let mut iter = index.entries();
    let mut entries = Vec::new();
    let mut first_elements = config_tree.get_first_level_items();
    let mut success_files_count: u32 = 0;
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
                                obj_node.encrypt.clone()
                            ) {
                                Ok((current_visited_files, count)) => {
                                    success_files_count += count;
                                    visited_files.extend(current_visited_files);
                                },
                                Err(e) => dprintln!("[ERROR] {}", e.to_string()),
                            }
                        }
                    }
                } else {
                    let (obj_name_san, ads) = match obj_name.split_once(':') {
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
                    if !visited_files.contains(&path_check)
                        && Pattern::new(&obj_name_san.as_str().to_lowercase())
                            .unwrap()
                            .matches(&new_path.as_str().to_lowercase())
                    {
                        if !&obj_name.contains("*") && !obj_node.all {
                            obj_node.checked = true;
                        }
    
                        if sub_file.is_directory() {
                            match process_directory(
                                fs,
                                ntfs,
                                &sub_file,
                                obj_node,
                                &new_path,
                                entry,
                                destination_folder,
                                visited_files,
                                drive
                            ){
                                Ok(count) => success_files_count += count,
                                Err(e) => dprintln!("[ERROR] {:?}", e),
                            }
                        }
                        if obj_node.children.is_empty() && !sub_file.is_directory() {
                            match get(
                                &sub_file,
                                &path_check,
                                destination_folder,
                                fs,
                                obj_node.encrypt.as_ref(),
                                ads,
                                drive,
                            ) {
                                Ok(_) => {
                                    success_files_count += 1;
                                    visited_files.insert(path_check);
                                }
                                Err(e) => dprintln!("[ERROR] {}", e.to_string()),
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

    Ok(success_files_count)
}

/// Entry point for parsing the NTFS partition and applying glob matching
fn explorer(ntfs_path: &str, config_tree: &mut Node, destination_folder: &str, drive: &str) -> Result<()> {
    // Open the NTFS partition for reading
    let file = File::open(ntfs_path)?;
    let sr = SectorReader::new(file, 4096)?;
    let mut fs = BufReader::new(sr);

    // Initialize NTFS parser
    let ntfs = initialize_ntfs(&mut fs)?;

    // Process the root directory
    let root_dir = ntfs.root_directory(&mut fs)?;

    // Start processing directories from root
    let mut visited_files: HashSet<String> = HashSet::new();

    let file_record_number = root_dir.file_record_number();
    let parent = Entry {
        name: "\\".to_string(),
        file_record_number,
    };
    match process_directory(
        &mut fs,
        &ntfs,
        &root_dir,
        config_tree,
        "",
        &parent,
        destination_folder,
        &mut visited_files,
        drive
    ) {
        Ok(count) => {
            dprintln!(
                "[INFO] Collection completed with {} collected files",
                count
            );
        },
        Err(e) => dprintln!("[ERROR] {:?}", e),
    }

    Ok(())
}

// Define the structure for the file tree
#[derive(Debug)]
struct Node {
    children: HashMap<String, Node>,
    checked: bool,
    all: bool, // if there is an **
    encrypt: Option<String>
}

impl Node {
    fn new_directory(all: bool, encrypt: Option<String>) -> Self {
        Node {
            children: HashMap::new(),
            checked: false,
            all,
            encrypt
        }
    }

    fn insert(&mut self, path: &str, files: Vec<String>, encrypt: Option<String>) {
        let parts: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if parts.is_empty() {
            for file in files {
                let file_path = format!("/{}", file);
                self.children.insert(
                    file_path.clone(),
                    Node {
                        children: HashMap::new(),
                        checked: false,
                        all: false,
                        encrypt: encrypt.clone()
                    },
                );
            }
            return;
        }

        let mut current = self;
        let mut current_path = String::new();
        let mut all = false;
        for (i, part) in parts.iter().enumerate() {
            if *part == "**" {
                all = true;
                // Get the rest of the parts from the current index onward
                let remaining_parts: Vec<_> = parts[i..].iter().cloned().collect();
                for file in &files {
                    let file_path =
                        format!("{}/{}/{}", current_path, remaining_parts.join("/"), file);
                    current.children.insert(
                        file_path.clone(),
                        Node {
                            children: HashMap::new(),
                            checked: false,
                            all: true,
                            encrypt: encrypt.clone()
                        },
                    );
                }
            } else {
                current_path.push('/');
                current_path.push_str(part);
                current = current
                    .children
                    .entry(current_path.clone())
                    .or_insert_with(|| {
                        Node::new_directory( *part == "**" || current.all, encrypt.clone())
                    });
            }
        }
        if !all {
            for file in files {
                let file_path = format!("{}/{}", current_path, file);
                current.children.insert(
                    file_path.clone(),
                    Node {
                        children: HashMap::new(),
                        checked: false,
                        all: current.all || file == "**",
                        encrypt: encrypt.clone(),
                    },
                );
            }
        }
    }

    fn get_first_level_items(&mut self) -> Vec<(&String, &mut Node)> {
        self.children
            .iter_mut()
            .map(|(name, node)| (name, node))
            .collect()
    }
}

pub fn process_drive_artifacts(
    drive: &str,
    section_config: &mut SectionConfig,
    root_output: &str,
) -> Result<()> {
    let drive_letter = drive.chars().next().unwrap();
    let output_path = format!("{}\\{}", root_output, drive_letter);

    ensure_directory_exists(&output_path)?;

    let ntfs_path: &str = &format!("\\\\.\\{}:", drive_letter);

    let mut config_entries: HashMap<String, (Vec<String>, Option<String>)> = HashMap::new();

    section_config
        .entries
        .iter_mut()
        .for_each(|(_, search_config_vec)| {
            search_config_vec.iter_mut().for_each(|search_config| {
                search_config
                    .sanitize()
                    .expect("[ERROR] Config sanitization failed");
                let encrypt_option = search_config.encrypt.clone();
                search_config.objects.iter().flatten().for_each(|object| {
                    let c_obj = split_path(&object.replace("\\", "/"));
                    let d_p: String = if c_obj.0.is_empty() {
                        let d = search_config.dir_path.clone().unwrap_or("/".to_string());
                        if d.is_empty() {
                            "/".to_string()
                        } else {
                            format!(
                                "{}",
                                search_config.dir_path.clone().unwrap_or("/".to_string())
                            )
                        }
                    } else {
                        format!(
                            "{}/{}",
                            search_config.dir_path.clone().unwrap_or("/".to_string()),
                            c_obj.0
                        )
                    };
                    let f_p = c_obj.1;
                    config_entries
                    .entry(d_p)
                    .or_insert_with(|| (Vec::new(), encrypt_option.clone()))
                    .0
                    .push(f_p);
                });
            });
        });

    let mut tree = Node::new_directory(false, None);

    // Populate the tree with the updated config_entries
    for (path, (files, encrypt)) in config_entries {
        tree.insert(&path, files, encrypt);
    }

    explorer(ntfs_path, &mut tree, &output_path.replace("\\", "/"), drive)?;

    Ok(())
}

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
