// src/explorer/native.rs
//
// SPDX-License-Identifier: Apache-2.0
//
// Author(s): Areg Baghinyan
//

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use crate::reader::fs::Node;
use crate::stream::OutputTarget;
use super::fs::FileSystemExplorer;

/// Explorer that walks a mounted POSIX filesystem using std::fs
pub struct NativeExplorer {
    /// Absolute path of the mount point we operate under (e.g. "/mnt/disk" or "/")
    mount_point: String,
}

impl NativeExplorer {
    pub fn new() -> Self {
        Self { mount_point: String::new() }
    }

    /// Resolve a device or directory to its mount point.
    /// - If `path` is already a directory (e.g. "/"), use it.
    /// - If `path` looks like a device (/dev/...), resolve from /proc/self/mountinfo first,
    ///   then /proc/mounts. Falls back to "/" if nothing matches.
    fn resolve_mount_point(path: &str) -> Option<String> {
        let p = Path::new(path);
        if p.is_dir() {
            return Some(path.to_string());
        }

        // Prefer /proc/self/mountinfo (format: ... <mount_point> ... - <fstype> <source> ...)
        if let Ok(file) = File::open("/proc/self/mountinfo") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if let Some(sep) = line.find(" - ") {
                    let (pre, post) = line.split_at(sep);
                    // fields: 0:id 1:parent 2:major:minor 3:root 4:mount_point ...
                    let mut pre_fields = pre.split_whitespace();
                    let mount_point = pre_fields.nth(4).unwrap_or("");
                    let mut post_fields = post.trim_start_matches(" - ").split_whitespace();
                    let _fstype = post_fields.next().unwrap_or("");
                    let source = post_fields.next().unwrap_or("");

                    if source == path {
                        return Some(mount_point.to_string());
                    }
                }
            }
        }

        // Fallback to /proc/mounts
        if let Ok(file) = File::open("/proc/mounts") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let device = parts[0];
                    let mount_point = parts[1];
                    if device == path {
                        return Some(mount_point.to_string());
                    }
                }
            }
        }

        None
    }

    /// Mirror the directory tree relative to self.mount_point and copy a single path.
    fn copy_file_preserve_tree(&self, abs_src: &Path, output: &OutputTarget, dest_prefix: &str) -> Result<()> {
        // Compute relative path under the mount point so we can mirror the tree
        let rel = abs_src.strip_prefix(&self.mount_point)
            .unwrap_or(abs_src);
        let rel_norm = rel.strip_prefix("/").unwrap_or(rel);
        let dst_path_str = format!("{}/{}", dest_prefix, rel_norm.to_string_lossy());

        let meta = fs::symlink_metadata(abs_src)
            .with_context(|| format!("symlink_metadata({})", abs_src.display()))?;

        if meta.is_file() {
            // Stream file through OutputTarget in 8KB chunks
            let mut src_file = File::open(abs_src)
                .with_context(|| format!("open({})", abs_src.display()))?;
            let mut writer = output.create_entry(&dst_path_str)
                .with_context(|| format!("create_entry({})", dst_path_str))?;
            let mut buf = [0u8; 8192];
            loop {
                let n = src_file.read(&mut buf)?;
                if n == 0 { break; }
                writer.write_all(&buf[..n])?;
            }
        } else if meta.is_dir() {
            output.ensure_dir(&dst_path_str)?;
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(abs_src)
                .with_context(|| format!("read_link({})", abs_src.display()))?;
            let real = if target.is_absolute() {
                target
            } else {
                abs_src.parent().unwrap_or_else(|| Path::new("/")).join(target)
            };
            if real.is_file() {
                let mut src_file = File::open(&real)
                    .with_context(|| format!("open({})", real.display()))?;
                let mut writer = output.create_entry(&dst_path_str)
                    .with_context(|| format!("create_entry({})", dst_path_str))?;
                let mut buf = [0u8; 8192];
                loop {
                    let n = src_file.read(&mut buf)?;
                    if n == 0 { break; }
                    writer.write_all(&buf[..n])?;
                }
            }
        }
        Ok(())
    }

    /// Pattern match identical to your ext4 path (supports optional ":ads" suffix in the pattern).
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

    /// Size cap identical to ext4 path.
    fn is_file_size_ok(file_len: u64, max_size: Option<u64>) -> bool {
        if let Some(limit) = max_size {
            if file_len > limit * 1024 * 1024 { return false; }
        }
        true
    }

    /// Recursively walk a directory (greedy/"**" behavior) and copy matching entries.
    /// We copy everything if `obj_name == "*"`, otherwise apply pattern.
    fn process_all_directory(
        &self,
        start_dir: &Path,
        obj_name: String,
        visited: &mut HashSet<String>,
        output: &OutputTarget,
        dest_prefix: &str,
        _encrypt: Option<String>, // encryption not implemented in native fallback
        max_size: Option<u64>,
        success_files_count: &mut u32,
    ) -> Result<()> {
        let mut stack: Vec<PathBuf> = vec![start_dir.to_path_buf()];

        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) => {
                    dprintln!("[WARN] read_dir {} failed: {}", dir.display(), e);
                    continue;
                }
            };

            for entry in entries.flatten() {
                let path = entry.path();

                // Convert to string (mirrors ext4 path erroring on non-UTF8)
                let entry_str = path.to_str().ok_or_else(|| {
                    anyhow::anyhow!("Non-UTF8 path: {:?}", path)
                })?.to_string();

                // Skip if visited
                if visited.contains(&entry_str) {
                    continue;
                }

                // Symlink handling: skip (consistent with ext4 branch)
                match entry.file_type() {
                    Ok(ft) if ft.is_symlink() => continue,
                    _ => {}
                }

                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        dprintln!("[WARN] metadata {} failed: {}", entry_str, e);
                        continue;
                    }
                };

                if meta.is_dir() {
                    visited.insert(entry_str.clone());
                    // Ensure directory exists in destination (mirror)
                    self.copy_file_preserve_tree(&path, output, dest_prefix)?;
                    stack.push(path);
                } else if meta.is_file() {
                    if obj_name == "*" || Self::is_pattern_match(&entry_str, &obj_name) {
                        if Self::is_file_size_ok(meta.len(), max_size) {
                            match self.copy_file_preserve_tree(&path, output, dest_prefix) {
                                Ok(_) => {
                                    dprintln!("[INFO] Data successfully saved to mirror path for {}", entry_str);
                                    visited.insert(entry_str);
                                    *success_files_count += 1;
                                }
                                Err(e) => {
                                    dprintln!("[ERROR] Failed to copy {}: {}", path.display(), e);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Main directory traversal mirroring ext4::process_directory behavior.
    fn process_directory(
        &self,
        current_path: &Path,
        config_tree: &mut Node,
        output: &OutputTarget,
        dest_prefix: &str,
        visited: &mut HashSet<String>,
        success_files_count: &mut u32,
    ) -> Result<u32> {
        let mut first = config_tree.get_first_level_items();

        // Handle "**" nodes once at this level
        for (_, node) in &mut first {
            if node.all && !node.checked {
                self.process_all_directory(
                    current_path,
                    "*".to_string(),
                    visited,
                    output,
                    dest_prefix,
                    node.encrypt.clone(),
                    node.max_size,
                    success_files_count,
                )?;
                node.checked = true;
            }
        }

        // Read entries of current directory
        let entries = match fs::read_dir(current_path) {
            Ok(rd) => rd.collect::<Result<Vec<_>, _>>()
                .with_context(|| format!("read_dir collect {}", current_path.display()))?,
            Err(e) => {
                dprintln!("[WARN] read_dir {} failed: {}", current_path.display(), e);
                return Ok(*success_files_count);
            }
        };

        for entry in entries {
            let path = entry.path();
            let entry_str = path.to_str().ok_or_else(|| {
                anyhow::anyhow!("Non-UTF8 path: {:?}", path)
            })?.to_string();

            // Skip symlinks
            if entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false) {
                continue;
            }
            // Skip if already handled
            if visited.contains(&entry_str) {
                continue;
            }

            for (obj_name, obj_node) in &mut first {
                if obj_node.all {
                    // already handled above at this level
                    continue;
                }

                if Self::is_pattern_match(&entry_str, obj_name) {
                    if !obj_name.contains('*') {
                        obj_node.checked = true;
                    }

                    let meta = match fs::metadata(&path) {
                        Ok(m) => m,
                        Err(e) => {
                            dprintln!("[WARN] metadata {} failed: {}", entry_str, e);
                            continue;
                        }
                    };

                    if meta.is_dir() {
                        // Mark visited before recursion to avoid re-walking
                        visited.insert(entry_str.clone());
                        // Mirror the directory node to destination
                        self.copy_file_preserve_tree(&path, output, dest_prefix)?;
                        // Recurse with the matching node
                        self.process_directory(
                            &path,
                            obj_node,
                            output,
                            dest_prefix,
                            visited,
                            success_files_count,
                        )?;
                    } else if obj_node.children.is_empty()
                        && meta.is_file()
                        && Self::is_file_size_ok(meta.len(), obj_node.max_size)
                    {
                        match self.copy_file_preserve_tree(&path, output, dest_prefix) {
                            Ok(_) => {
                                visited.insert(entry_str.clone());
                                dprintln!("[INFO] Data successfully saved to mirror path for {}", entry_str);
                                *success_files_count += 1;
                            }
                            Err(e) => dprintln!("[ERROR] {}", e),
                        }
                    }
                }
            }

            if first.iter().all(|(_, node)| node.checked) {
                break;
            }
        }

        Ok(*success_files_count)
    }
}

impl FileSystemExplorer for NativeExplorer {
    fn initialize(&mut self, path: &str) -> Result<()> {
        // Accept directories or resolve devices; if resolution fails, fall back to "/"
        self.mount_point = Self::resolve_mount_point(path)
            .or_else(|| {
                // If `path` was a device that we couldn't resolve, try "/" so we still work.
                dprintln!("[WARN] Could not resolve mount point for `{}`, falling back to `/`", path);
                Some("/".to_string())
            })
            .unwrap();
        Ok(())
    }

    fn collect(&mut self, config_tree: &mut Node, output: &OutputTarget, dest_prefix: &str, drive: &str) -> Result<()> {
        output.ensure_dir(dest_prefix)?;

        let start = Path::new(&self.mount_point);
        let mut visited = HashSet::new();
        let mut count = 0u32;

        self.process_directory(start, config_tree, output, dest_prefix, &mut visited, &mut count)?;
        dprintln!("Finished processing of drive {}", drive);
        Ok(())
    }
}
