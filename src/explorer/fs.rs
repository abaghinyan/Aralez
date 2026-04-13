//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Areg Baghinyan, Razmik Arshakyan
//

use crate::reader::fs::Node;
use crate::stream::OutputTarget;
use anyhow::Result;

#[cfg(not(target_os = "macos"))]
use super::ntfs::NtfsExplorer;

#[cfg(target_os = "linux")]
use super::ext4::Ext4Explorer;

#[cfg(target_os = "linux")]
use super::native::NativeExplorer; 

#[cfg(target_os = "macos")]
use super::native::NativeExplorer;

pub trait FileSystemExplorer {
    fn initialize(
        &mut self,
        path: &str) -> Result<()>;
    fn collect(
        &mut self,
        config_tree: &mut Node,
        output: &OutputTarget,
        dest_prefix: &str,
        drive: &str) -> Result<()>;
}

#[allow(dead_code)]
pub enum FileSystemType {
    NTFS,
    EXT4,
    APFS,
    HFSPlus,
    PosixFallback
    // Other File Systems TODO
}

pub fn create_explorer(fs_type: FileSystemType) -> Result<Box<dyn FileSystemExplorer>> {
    match fs_type {
        #[cfg(not(target_os = "macos"))]
        FileSystemType::NTFS => Ok(Box::new(NtfsExplorer::new())),
        #[cfg(target_os = "macos")]
        FileSystemType::NTFS => Err(anyhow::anyhow!("NTFS exploration is not supported on macOS")),

        FileSystemType::APFS => {
            #[cfg(target_os = "macos")]
            { Ok(Box::new(super::apfs::ApfsExplorer::new())) }
            #[cfg(not(target_os = "macos"))]
            { Err(anyhow::anyhow!("APFS exploration is only configured for execution on macOS target right now")) }
        },

        FileSystemType::HFSPlus => {
            #[cfg(target_os = "macos")]
            { Ok(Box::new(super::hfsplus::HfsPlusExplorer::new())) }
            #[cfg(not(target_os = "macos"))]
            { Err(anyhow::anyhow!("HFS+ exploration is only configured for execution on macOS target right now")) }
        },

        #[cfg(target_os = "linux")]
        FileSystemType::EXT4 => Ok(Box::new(Ext4Explorer::new())),

        #[cfg(not(target_os = "linux"))]
        FileSystemType::EXT4 => Err(anyhow::anyhow!("EXT4 is only supported on Linux")),

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        FileSystemType::PosixFallback => Ok(Box::new(NativeExplorer::new())),

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        FileSystemType::PosixFallback => Err(anyhow::anyhow!("POSIX fallback is not supported on this platform")),
    }
}

