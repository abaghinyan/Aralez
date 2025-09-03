//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::explorer::fs::{create_explorer, FileSystemType};
use crate::config::SectionConfig;
use crate::utils::split_path;
use anyhow::Result;
use std::collections::HashMap;
use std::u64;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[cfg(target_os = "linux")]
use std::path::Path;

pub fn is_ntfs_partition<T: Read + Seek>(reader: &mut T) -> Result<bool> {
    const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
    let mut boot_sector = [0u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    match reader.read_exact(&mut boot_sector) {
        Ok(_) => Ok(&boot_sector[3..11] == NTFS_SIGNATURE),
        Err(_) => Ok(false),
    }
}

pub fn is_ext4_partition<T: Read + Seek>(reader: &mut T) -> Result<bool>
{
    const SUPERBLOCK_OFFSET: u64 = 1024;
    const EXT_SUPERBLOCK_SIZE: usize = 1024;
    const EXT4_MAGIC_OFFSET: usize = 56;
    const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

    let mut superblock = [0u8; EXT_SUPERBLOCK_SIZE];

    // Any failure to seek/read means "not ext4" instead of bubbling an error.
    if reader.seek(SeekFrom::Start(SUPERBLOCK_OFFSET)).is_err() {
        return Ok(false);
    }
    if reader.read_exact(&mut superblock).is_err() {
        return Ok(false);
    }

    Ok(&superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2] == EXT4_MAGIC)
}

#[cfg(target_os = "linux")]
pub fn get_default_drive() -> String {
    use std::io::{BufRead, BufReader};

    // 1) Try /proc/self/mountinfo (most informative)
    if let Ok(file) = File::open("/proc/self/mountinfo") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            // Format: ... mount_point ... - fstype source superopts
            // Split at the " - " separator
            if let Some(sep) = line.find(" - ") {
                let (pre, post) = line.split_at(sep);
                // pre: fields where 5th whitespace-separated field is mount point
                let mut pre_fields = pre.split_whitespace();
                // fields: 0:id 1:parent 2:major:minor 3:root 4:mount_point ...
                let mount_point = pre_fields.nth(4).unwrap_or("");

                if mount_point == "/" {
                    let mut post_fields = post.trim_start_matches(" - ").split_whitespace();
                    let _fstype = post_fields.next().unwrap_or("");
                    let source = post_fields.next().unwrap_or("");

                    // If it’s a real block device, use it
                    if source.starts_with("/dev/") {
                        return source.to_string();
                    }
                    // Some distros expose /dev/root → real device symlink
                    if Path::new("/dev/root").exists() {
                        return "/dev/root".to_string();
                    }
                    // Fall back to returning the mount point itself; our fallback explorer handles dirs
                    return "/".to_string();
                }
            }
        }
    }

    // 2) Fallback: /proc/mounts
    if let Ok(file) = File::open("/proc/mounts") {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let device = parts[0];
                let mount_point = parts[1];
                if mount_point == "/" {
                    if device.starts_with("/dev/") {
                        return device.to_string();
                    }
                    if Path::new("/dev/root").exists() {
                        return "/dev/root".to_string();
                    }
                    return "/".to_string();
                }
            }
        }
    }

    // 3) Last resort: the root mount point
    "/".to_string()
}

#[cfg(target_os = "windows")]
pub fn get_default_drive() -> String {
    "C".to_string()
}

fn get_fs_type(drive_path: &str) -> Result<FileSystemType> {
    if let Ok(mut file) = File::open(&drive_path) {
        if is_ntfs_partition(&mut file)? {
            return Ok(FileSystemType::NTFS);
        }
        if is_ext4_partition(&mut file)? {
            // Prefer PosixFallback when not a real block device path
            #[cfg(target_os = "linux")]
            if !drive_path.starts_with("/dev/") {
                return Ok(FileSystemType::PosixFallback);
            }
            return Ok(FileSystemType::EXT4);
        }
        #[cfg(target_os = "linux")]
        return Ok(FileSystemType::PosixFallback);
        #[cfg(not(target_os = "linux"))]
        return Err(anyhow::anyhow!("Given File System is not supported"));
    }
    Err(anyhow::anyhow!("File Open Error"))
}

/// Entry point for parsing the FS partition and applying glob matching
fn explorer(drive_path: &str, config_tree: &mut Node, destination_folder: &str, drive: &str) -> Result<()> {
    let fs_type = get_fs_type(drive_path)?;
    let mut fs_explorer = create_explorer(fs_type)?;
    if let Err(e) = (|| -> Result<()> {
        fs_explorer.initialize(&drive_path)?;
        fs_explorer.collect(config_tree, destination_folder, drive)?;
        Ok(())
    })() {
        // If we hit a journal-feature incompatibility, fall back on Linux.
        #[cfg(target_os = "linux")]
        {
            if e.to_string().contains("incompatible filesystem: missing required journal features") {
                let mut fallback = create_explorer(FileSystemType::PosixFallback)?;
                fallback.initialize(&drive_path)?;
                fallback.collect(config_tree, destination_folder, drive)?;
                return Ok(())
            }
        }
        return Err(e);
    }
    Ok(())
}

// Define the structure for the file tree
#[derive(Debug)]
pub struct Node {
    pub children: HashMap<String, Node>,
    pub checked: bool,
    pub all: bool, // if there is an **
    pub encrypt: Option<String>,
    pub max_size: Option<u64>,
}

impl Node {
    fn new_directory(all: bool, encrypt: Option<String>, max_size: Option<u64>) -> Self {
        Node {
            children: HashMap::new(),
            checked: false,
            all,
            encrypt,
            max_size
        }
    }

    fn insert(&mut self, path: &str, files: Vec<String>, encrypt: Option<String>, max_size: Option<u64>) {
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
                        encrypt: encrypt.clone(),
                        max_size
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
                            encrypt: encrypt.clone(),
                            max_size
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
                        Node::new_directory( *part == "**" || current.all, encrypt.clone(), max_size)
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
                        max_size
                    },
                );
            }
        }
    }

    pub fn get_first_level_items(&mut self) -> Vec<(&String, &mut Node)> {
        self.children
            .iter_mut()
            .map(|(name, node)| (name, node))
            .collect()
    }
}

pub fn process_drive_artifacts(
    drive: &str,
    section_config: &mut SectionConfig,
    output_path: &str,
) -> Result<()> {
    let drive_path: String = if cfg!(target_os = "windows") {
        format!("\\\\.\\{}:", drive.chars().next().unwrap())
    } else {
        drive.to_string()
    };

    let mut config_entries: HashMap<String, (Vec<String>, Option<String>, Option<u64>)> = HashMap::new();
    if let Some(ref mut entries) = section_config.entries {
        entries
        .iter_mut()
        .for_each(|(_, search_config_vec)| {
            search_config_vec.iter_mut().for_each(|search_config| {
                search_config
                    .sanitize()
                    .expect("[ERROR] Config sanitization failed");
                let encrypt_option = search_config.encrypt.clone();
                let max_size = search_config.get_max_size(section_config.max_size);
                search_config.objects.iter().flatten().for_each(|object| {
                    let c_obj = split_path(&object.replace("\\", "/"));
                    let d_p: String = if c_obj.0.is_empty() {
                        let d = search_config.root_path.clone().unwrap_or("/".to_string());
                        if d.is_empty() {
                            "/".to_string()
                        } else {
                            format!(
                                "{}",
                                search_config.root_path.clone().unwrap_or("/".to_string())
                            )
                        }
                    } else {
                        format!(
                            "{}/{}",
                            search_config.root_path.clone().unwrap_or("/".to_string()),
                            c_obj.0
                        )
                    };
                    let f_p = c_obj.1;
                    config_entries
                    .entry(d_p)
                    .or_insert_with(|| (Vec::new(), encrypt_option.clone(), max_size))
                    .0
                    .push(f_p);
                });
            });
        });
    }

    let mut tree = Node::new_directory(false, None, None);

    // Populate the tree with the updated config_entries
    for (path, (files, encrypt, max_size)) in config_entries {
        tree.insert(&path, files, encrypt, max_size);
    }

    explorer(&drive_path, &mut tree, &output_path.replace("\\", "/"), drive)?;

    Ok(())
}
