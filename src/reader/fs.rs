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

/// Entry point for parsing the FS partition and applying glob matching
fn explorer(path: &str, config_tree: &mut Node, destination_folder: &str, drive: &str) -> Result<()> {
    // TODO (Write logic for getting the type from given drive <EXT4> or <NTFS>)
    let fs_type = if cfg!(target_os = "windows") {
        FileSystemType::NTFS
    } else {
        FileSystemType::EXT4
    };
    let mut fs_explorer = create_explorer(fs_type)?;
    fs_explorer.initialize(&path)?;
    fs_explorer.collect(config_tree, destination_folder, drive)?;

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
