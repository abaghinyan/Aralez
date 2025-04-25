//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Razmik Arshakyan
//

use crate::fs_reader::*;
use std::collections::HashSet;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::io::{BufWriter, Write};
use std::fs::File;

#[cfg(target_os = "linux")]
use ext4_view::{Ext4, FileType};

pub struct Ext4Explorer {
    parser: Option<Ext4>,
}

impl Ext4Explorer {
    pub fn new() -> Self 
    {
        Ext4Explorer {
            parser: None,
        }
    }
    
    // Function for getting file_data and pasting it's content into
    // destination folder, for forensic investigation
    fn get(
        &self,
        file_data: Vec<u8>,
        file_name: &str,
        dest_folder: &Path) -> Result<bool>
    {
        let path: PathBuf = dest_folder.join(file_name);
        let file = File::create(&path)?;
        let mut buf_writer = BufWriter::new(file);
        buf_writer.write_all(&file_data)?;
        buf_writer.flush()?;
        Ok(true)
    }

    // Checks whether specified pattern in <objects> field
    // of config.yml matches file_path
    fn is_pattern_match(
        &self,
        file_path: &str,
        obj_name: &str) -> bool
    {
        let (base_fn, alternate_ds) = obj_name.split_once(':')
            .map(|(l, r)| (l.to_string(), r))
            .unwrap_or((obj_name.to_string(), ""));
        let mut path_check = file_path.to_string();
        if false == alternate_ds.is_empty() {
            path_check = format!("{}:{}", path_check, alternate_ds);
        }

        glob::Pattern::new(&base_fn.to_lowercase())
            .map(|p| p.matches(&path_check.to_lowercase()))
            .unwrap_or(false)
    }

    // Check whether file size is consistent with max size specified 
    // in config.yml
    fn is_file_size_ok(
        &self,
        file_len: u64,
        max_size: Option<u64>) -> bool
    {
        if let Some(limit) = max_size {
            if file_len > limit {
                return false;
            }
        }
        true
    }

    // Routine used for traversing through filesytem in case of
    // ** regex written in config.yml
    fn process_all_directory(
        &self,
        path: &Path,
        obj_name: String,
        dest_folder: &Path,
        encrypt: Option<String>,
        max_size: Option<u64>,
        success_files_count: &mut u32) -> Result<HashSet<String>>
    {
        let mut visited = HashSet::new();

        let entries = {
            let parser = self.parser.as_ref().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "parser not initialized")
            })?;

            let path_str = path.to_string_lossy().into_owned();
            parser.read_dir(&path_str)?.collect::<Result<Vec<_>, _>>()?
        };

        for entry in entries {
            let path_buf = entry.path();
            let entry_str = path_buf.to_str().unwrap().to_string();

            if entry.file_name() == "." || entry.file_name() == ".."
                || FileType::Symlink == entry.file_type()? {
                continue;
            }

            let metadata = {
                let parser = self.parser.as_ref().unwrap();
                parser.metadata(&entry_str)?
            };

            if metadata.is_dir() {
                let collected_files = self.process_all_directory(
                    path_buf.as_path().into(), obj_name.clone(), dest_folder,
                    encrypt.clone(), max_size, success_files_count,
                )?;
                visited.extend(collected_files);
            } else if self.is_pattern_match(&entry_str, &obj_name) {
                if self.is_file_size_ok(metadata.len(), max_size) {
                    let file_name =Path::new(&entry_str)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("<no file name>");
                    let file_data =
                        self.parser.as_ref().unwrap().read(path_buf.as_path())?;
                    match self.get(
                        file_data,
                        file_name,
                        dest_folder)
                    {
                        Ok(written) => {
                            if written {
                                dprintln!("Wrote {} bytes of data into \
                                    file {}", metadata.len(), file_name);
                                visited.insert(entry_str.clone());
                                *success_files_count += 1;
                            }
                        }
                        Err(e) => eprintln!("{}", e.to_string())
                    }
                }
            }
        }
        Ok(visited)
    }

    // Main routine for traversing directories, for artifact extraction
    pub fn process_directory(
        &self,
        current_path: &Path,
        config_tree: &mut Node,
        dest_folder: &Path,
        visited_files: &mut HashSet<String>,
        success_files_count: &mut u32,
    ) -> Result<u32> {
        let mut first_elements = config_tree.get_first_level_items();

        let path_str = current_path.to_string_lossy().into_owned();
        let entries = {
            let parser = self.parser.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "parser not initialized",
                )
            })?;
            parser.read_dir(&path_str)?
        };

        for entry in entries {
            let entry = entry?;
            let path_buf = entry.path();
            let entry_str = path_buf.to_str().unwrap().to_string();

            if entry.file_name() == "." || entry.file_name() == ".."
                || FileType::Symlink == entry.file_type()? {
                continue;
            }

            for (obj_name, obj_node) in &mut first_elements {
                if obj_node.all {
                    let current_path_str = current_path.to_string_lossy().to_string();
                    if !visited_files.contains(&current_path_str) {
                        let current_visited = self.process_all_directory(
                            current_path,
                            obj_name.to_string(),
                            dest_folder,
                            obj_node.encrypt.clone(),
                            obj_node.max_size,
                            success_files_count,
                        )?;
                        visited_files.extend(current_visited);
                    }
                } else if self.is_pattern_match(&entry_str, obj_name) {
                    if !obj_name.contains('*') {
                        obj_node.checked = true;
                    }

                    let parser = self.parser.as_ref().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::Other, "parser not initialized")
                    })?;

                    let metadata = parser.metadata(&entry_str)?;

                    if metadata.is_dir() {
                        self.process_directory(
                            entry.path().as_path().into(),
                            obj_node,
                            dest_folder,
                            visited_files,
                            success_files_count,
                        )?;
                    } else if obj_node.children.is_empty()
                        && self.is_file_size_ok(metadata.len(), obj_node.max_size)
                    {
                        let file_name =Path::new(&entry_str)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("<no file name>");
                        let file_data = parser.read(path_buf.as_path())?;
                        match self.get(
                            file_data,
                            file_name,
                            dest_folder)
                        {
                            Ok(written) => {
                                if written {
                                    visited_files.insert(entry_str.clone());
                                    dprintln!("Wrote {} bytes of data into \
                                        file {}", metadata.len(), file_name);
                                    *success_files_count += 1;
                                }
                            }
                            Err(e) => eprintln!("{}", e.to_string())
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
}

impl FileSystemExplorer for Ext4Explorer {
    // Initialize Ext4Explorer, to be ready for artifact extraction
    fn initialize(
        &mut self,
        path: &str) -> Result<()>
    {
        let path_buf = PathBuf::from(path);
        self.parser = Some(Ext4::load_from_path(&path_buf)?);
        Ok(())
    }
    
    // Processing directories from root, by extracting required artifacts
    fn collect(
        &mut self,
        config_tree: &mut Node,
        dest_folder: &str,
        drive: &str) -> Result<()>
    {
        let path = Path::new("/");
        let mut visited = HashSet::new();
        let mut count = 0;
        let dest: &Path = Path::new(&dest_folder);
        self.process_directory(path, config_tree, 
            &dest, &mut visited, &mut count)?;
        dprintln!("Finished processing of drive {}", drive);
        Ok(())
    }
}

