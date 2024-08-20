//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use ntfs::{Ntfs, NtfsFile};
use std::io::{Read, Seek};

/// Struct holding information about the current state of the command, including
/// the current directory, filesystem reader, and the NTFS structure.
pub struct CommandInfo<'n, T>
where
    T: Read + Seek,
{
    pub current_directory: Vec<NtfsFile<'n>>,   // Stack of directories currently being navigated
    pub fs: T,                                  // Filesystem reader
    pub ntfs: &'n Ntfs,                         // Reference to the NTFS structure
}

impl<'n, T> CommandInfo<'n, T>
where
    T: Read + Seek,
{
    pub fn new(mut fs: T, ntfs: &'n Ntfs) -> Result<Self, ntfs::NtfsError> {
        let current_directory = vec![ntfs.root_directory(&mut fs)?];
        Ok(CommandInfo {
            current_directory,
            fs,
            ntfs,
        })
    }
}
