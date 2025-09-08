//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Areg Baghinyan, Razmik Arshakyan
//

use std::collections::HashSet;
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use ext4_view::{Ext4, FileType};

use super::fs::Node;

// Function for getting file_data and writing its content into
// destination folder, for forensic investigation.
fn get(file_data: Vec<u8>, file_name: &str, dest_folder: &Path) -> Result<(bool, String)> {
    let relative = file_name.trim_start_matches('/');
    let out_path: PathBuf = dest_folder.join(relative);

    if let Some(parent) = out_path.parent() {
        create_dir_all(parent)?;
    }

    let file = File::create(&out_path)?;
    let mut buf_writer = BufWriter::with_capacity(8 * 1024, file);

    let mut offset = 0;
    let total = file_data.len();
    while offset < total {
        let end = std::cmp::min(offset + 8 * 1024, total);
        buf_writer.write_all(&file_data[offset..end])?;
        offset = end;
    }
    buf_writer.flush()?;

    let file_location: String = out_path.to_string_lossy().into_owned();
    dprintln!(
        "[INFO] Saving {} bytes of data in {}",
        file_data.len(),
        file_location
    );
    Ok((true, file_location))
}

// Checks whether specified pattern in <objects> field of config.yml matches file_path
fn is_pattern_match(file_path: &str, obj_name: &str) -> bool {
    let (base_fn, alternate_ds) = obj_name
        .split_once(':')
        .map(|(l, r)| (l.to_string(), r))
        .unwrap_or((obj_name.to_string(), ""));
    let mut path_check = file_path.to_string();
    if !alternate_ds.is_empty() {
        path_check = format!("{}:{}", path_check, alternate_ds);
    }

    glob::Pattern::new(&base_fn.to_lowercase())
        .map(|p| p.matches(&path_check.to_lowercase()))
        .unwrap_or(false)
}

// Check whether file size is consistent with max size specified in config.yml
fn is_file_size_ok(file_len: u64, max_size: Option<u64>) -> bool {
    if let Some(limit) = max_size {
        if file_len > limit * 1024 * 1024  {
            return false;
        }
    }
    true
}

// Routine used for traversing through filesystem in case of ** regex in config.yml.
// Important: directories are marked visited to avoid re-walking via other paths.
fn process_all_directory(
    ext4_parser: &Ext4,
    path: &Path,
    obj_name: String,
    visited_files: &mut HashSet<String>,
    dest_folder: &Path,
    _encrypt: Option<String>, // encryption not implemented for ext4 branch
    max_size: Option<u64>,
    success_files_count: &mut u32,
) -> Result<()> {
    let entries = {
        let path_str = path.to_string_lossy().into_owned();
        ext4_parser
            .read_dir(&path_str)?
            .collect::<Result<Vec<_>, _>>()?
    };

    for entry in entries {
        let path_buf = entry.path();

        // ext4_view::PathBuf -> &str
        let entry_str = match path_buf.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Non-UTF8 path: {:?}, error: {}",
                    path_buf,
                    e
                ))
            }
        };

        // Skip dot entries & symlinks
        if entry.file_name() == "." || entry.file_name() == ".." || entry.file_type()? == FileType::Symlink {
            continue;
        }

        if visited_files.contains(&entry_str) {
            continue;
        }

        let metadata = ext4_parser.metadata(&entry_str)?;
        if metadata.is_dir() {
            // mark dir visited to avoid reprocessing from elsewhere
            visited_files.insert(entry_str.clone());
            process_all_directory(
                ext4_parser,
                // ext4_view::Path<'_> -> &std::path::Path
                path_buf.as_path().into(),
                obj_name.clone(),
                visited_files,
                dest_folder,
                _encrypt.clone(),
                max_size,
                success_files_count,
            )?;
        } else if is_pattern_match(&entry_str, &obj_name) && is_file_size_ok(metadata.len(), max_size) {
            match ext4_parser.read(path_buf.as_path()) {
                Ok(file_data) => match get(file_data, &entry_str, dest_folder) {
                    Ok((written, location)) => {
                        if written {
                            dprintln!("[INFO] Data successfully saved to {}", location);
                            visited_files.insert(entry_str.clone());
                            *success_files_count += 1;
                        }
                    }
                    Err(e) => {
                        dprintln!("[ERROR] Failed to save {}: {}", entry_str, e);
                    }
                },
                Err(e) => {
                    dprintln!(
                        "[WARN] Skipping unreadable or special file {}: {}",
                        entry_str, e
                    );
                    continue;
                }
            }
        }
    }
    Ok(())
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

    // Handle "**" (all) nodes ONCE per current_path to avoid infinite loops.
    for (_, node) in &mut first_elements {
        if node.all && !node.checked {
            process_all_directory(
                ext4_parser,
                current_path,
                // The obj_name still matters because matching may include ADS suffix
                "*".to_string(),
                visited_files,
                dest_folder,
                node.encrypt.clone(),
                node.max_size,
                success_files_count,
            )?;
            node.checked = true; // prevent re-running at this level
        }
    }

    let entries = {
        let path_str = current_path.to_string_lossy().into_owned();
        ext4_parser
            .read_dir(&path_str)?
            .collect::<Result<Vec<_>, _>>()?
    };

    for entry in entries {
        let path_buf = entry.path();

        // ext4_view::PathBuf -> &str
        let entry_str = match path_buf.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Non-UTF8 path: {:?}, error: {}",
                    path_buf,
                    e
                ))
            }
        };

        // Skip dot entries & symlinks
        if matches!(entry.file_name().as_str(), Ok(".") | Ok(".."))
            || matches!(entry.file_type()?, FileType::Symlink)
        {
            continue;
        }

        // Skip if we've already handled this path (file OR directory)
        if visited_files.contains(&entry_str) {
            continue;
        }

        for (obj_name, obj_node) in &mut first_elements {
            if obj_node.all {
                // already handled above for this directory
                continue;
            }

            if is_pattern_match(&entry_str, obj_name) {
                if !obj_name.contains('*') {
                    obj_node.checked = true;
                }

                let metadata = ext4_parser.metadata(&entry_str)?;
                if metadata.is_dir() {
                    // mark dir visited before recursion to avoid re-walking via another pattern
                    visited_files.insert(entry_str.clone());
                    process_directory(
                        ext4_parser,
                        // ext4_view::Path<'_> -> &std::path::Path
                        path_buf.as_path().into(),
                        obj_node,
                        dest_folder,
                        visited_files,
                        success_files_count,
                    )?;
                } else if obj_node.children.is_empty()
                    && is_file_size_ok(metadata.len(), obj_node.max_size)
                {
                    let file_data = ext4_parser.read(path_buf.as_path())?;
                    match get(file_data, &entry_str, dest_folder) {
                        Ok((written, location)) => {
                            if written {
                                visited_files.insert(entry_str.clone());
                                dprintln!("[INFO] Data successfully saved to {}", location);
                                *success_files_count += 1;
                            }
                        }
                        Err(e) => eprintln!("{}", e.to_string()),
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
