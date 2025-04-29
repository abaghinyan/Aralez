//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Razmik Arshakyan
//

use std::collections::HashSet;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::fs::File;
use anyhow::Result;
use ext4_view::{Ext4, FileType};

use super::fs::Node;


// Function for getting file_data and pasting it's content into
// destination folder, for forensic investigation
fn get(
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
    ext4_parser: &Ext4,
    path: &Path,
    obj_name: String,
    dest_folder: &Path,
    encrypt: Option<String>,
    max_size: Option<u64>,
    success_files_count: &mut u32) -> Result<HashSet<String>>
{
    let mut visited = HashSet::new();

    let entries = {
        let path_str = path.to_string_lossy().into_owned();
        ext4_parser.read_dir(&path_str)?.collect::<Result<Vec<_>, _>>()?
    };

    for entry in entries {
        let path_buf = entry.path();
        let entry_str = path_buf.to_str().unwrap().to_string();

        if entry.file_name() == "." || entry.file_name() == ".."
            || FileType::Symlink == entry.file_type()? {
            continue;
        }

        let metadata = ext4_parser.metadata(&entry_str)?;

        if metadata.is_dir() {
            let collected_files = process_all_directory(
                ext4_parser, path_buf.as_path().into(), obj_name.clone(), dest_folder,
                encrypt.clone(), max_size, success_files_count,
            )?;
            visited.extend(collected_files);
        } else if is_pattern_match(&entry_str, &obj_name) {
            if is_file_size_ok(metadata.len(), max_size) {
                let file_name =Path::new(&entry_str)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<no file name>");
                let file_data = ext4_parser.read(path_buf.as_path())?;
                match get(
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
    ext4_parser: &Ext4,
    current_path: &Path,
    config_tree: &mut Node,
    dest_folder: &Path,
    visited_files: &mut HashSet<String>,
    success_files_count: &mut u32,
) -> Result<u32> {
    let mut first_elements = config_tree.get_first_level_items();

    let entries = {
        let path_str = current_path.to_string_lossy().into_owned();
        ext4_parser.read_dir(&path_str)?.collect::<Result<Vec<_>, _>>()?
    };

    for entry in entries {
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
                    let current_visited = process_all_directory(
                        ext4_parser,
                        current_path,
                        obj_name.to_string(),
                        dest_folder,
                        obj_node.encrypt.clone(),
                        obj_node.max_size,
                        success_files_count,
                    )?;
                    visited_files.extend(current_visited);
                }
            } else if is_pattern_match(&entry_str, obj_name) {
                if !obj_name.contains('*') {
                    obj_node.checked = true;
                }

                let metadata = ext4_parser.metadata(&entry_str)?;

                if metadata.is_dir() {
                    process_directory(
                        ext4_parser,
                        entry.path().as_path().into(),
                        obj_node,
                        dest_folder,
                        visited_files,
                        success_files_count,
                    )?;
                } else if obj_node.children.is_empty()
                    && is_file_size_ok(metadata.len(), obj_node.max_size)
                {
                    let file_name =Path::new(&entry_str)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("<no file name>");
                    let file_data = ext4_parser.read(path_buf.as_path())?;
                    match get(
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