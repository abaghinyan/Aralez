//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Razmik Arshakyan
//

use std::io::BufReader;
use crate::fs_reader::*;
use crate::sector_reader::SectorReader;
use ntfs::Ntfs;
use std::collections::HashSet;
use std::fs::File;
use anyhow::Result;

pub struct NtfsExplorer {
    fs_reader: Option<BufReader<SectorReader<File>>>,
    ntfs_parser: Option<Ntfs>,
}

impl NtfsExplorer {
    pub fn new() -> Self {
        NtfsExplorer {
            fs_reader: None,
            ntfs_parser: None,
        }
    }
}

impl FileSystemExplorer for NtfsExplorer {
    // Initialize NtfsExplorer, to be ready for artifact extraction
    fn initialize(
        &mut self,
        path: &str) -> Result<()> 
    {
        let file = File::open(path)?;
        let sr = SectorReader::new(file, 4096)?;
        let mut fs_reader = BufReader::new(sr);

        let ntfs = initialize_ntfs(&mut fs_reader)?;

        // Store values in struct
        self.fs_reader = Some(fs_reader);
        self.ntfs_parser = Some(ntfs);

        Ok(())
    }

    // Processing directories from root, by exctracting required artifacts
    fn collect(
        &mut self,
        config_tree: &mut Node,
        dest_folder: &str,
        drive: &str)  -> Result<()>
    {
        let fs_reader = self.fs_reader.as_mut().ok_or_else(|| std::io::Error::new
            (std::io::ErrorKind::Other, "fs_reader not initialized"))?;
        let ntfs_parser = self.ntfs_parser.as_ref().ok_or_else(|| std::io::Error::new
            (std::io::ErrorKind::Other, "ntfs_parser not initialized"))?;

        let root = ntfs_parser.root_directory(fs_reader)?;
        let mut visited_files = HashSet::new();
        let parent = Entry {
            name: "\\".to_string(),
            file_record_number: root.file_record_number(),
        };
        let mut success_files_count: u32 = 0;
        match process_directory(fs_reader, ntfs_parser, &root, config_tree, "", 
            &parent, dest_folder, &mut visited_files, drive, &mut success_files_count)
        {
            Ok(count) => {
                println!("[INFO] Collection completed with {} collected files",
                    count);
            },
            Err(e) => println!("[ERROR] Problem to process the folder: {:?}", e),
        }
        Ok(())
    }
}
