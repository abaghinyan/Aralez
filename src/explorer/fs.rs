//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Razmik Arshakyan
//

use anyhow::Result;

use crate::reader::fs::Node;

use super::ntfs::NtfsExplorer;

#[cfg(target_os = "linux")]
use super::ext4::Ext4Explorer;

pub trait FileSystemExplorer {
    fn initialize(
        &mut self,
        path: &str) -> Result<()>;
    fn collect(
        &mut self,
        config_tree: &mut Node,
        destination_folder: &str,
        drive: &str) -> Result<()>;
}

pub enum FileSystemType {
    NTFS,
    EXT4,
    // Other File Systems TODO
}

pub fn create_explorer(
    fs_type: FileSystemType) -> Result<Box<dyn FileSystemExplorer>>
{
    match fs_type {
        #[cfg(target_os = "windows")]
        FileSystemType::NTFS => Ok(Box::new(NtfsExplorer::new())),

        #[cfg(not(target_os = "windows"))]
        FileSystemType::NTFS => Ok(Box::new(NtfsExplorer::new())),

        #[cfg(target_os = "linux")]
        FileSystemType::EXT4 => Ok(Box::new(Ext4Explorer::new())),

        #[cfg(not(target_os = "linux"))]
        FileSystemType::EXT4 => Err(anyhow::anyhow!("EXT4 is only supported on Linux")),
    }
    // Other File Systems TODO
}
