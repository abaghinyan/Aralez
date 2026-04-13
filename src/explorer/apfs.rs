//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//

use crate::reader::fs::*;
use crate::reader::apfs::{initialize_apfs, process_directory};
use crate::reader::sector::SectorReader;
use crate::stream::OutputTarget;
use std::io::BufReader;
use std::collections::HashSet;
use std::fs::File;
use anyhow::Result;
use super::fs::FileSystemExplorer;

pub struct ApfsExplorer {
    fs_reader: Option<BufReader<SectorReader<File>>>,
}

impl ApfsExplorer {
    pub fn new() -> Self {
        ApfsExplorer {
            fs_reader: None,
        }
    }
}

impl FileSystemExplorer for ApfsExplorer {
    fn initialize(&mut self, path: &str) -> Result<()> {
        let file = File::open(path)?;
        let sr = SectorReader::new(file, 4096)?;
        let fs_reader = BufReader::new(sr);

        // Store values in struct
        self.fs_reader = Some(fs_reader);

        Ok(())
    }

    fn collect(
        &mut self,
        config_tree: &mut Node,
        output: &OutputTarget,
        dest_prefix: &str,
        drive: &str
    ) -> Result<()> {
        let fs_reader = self.fs_reader.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "fs_reader not initialized")
        })?;

        let mut visited_files: HashSet<String> = HashSet::new();
        let mut success_files_count: u32 = 0;

        let apfs_ctx = initialize_apfs(fs_reader)?;
        
        match process_directory(
            fs_reader,
            &apfs_ctx,
            "/",
            config_tree,
            "",
            output,
            dest_prefix,
            &mut visited_files,
            drive,
            &mut success_files_count
        ) {
            Ok(count) => {
                dprintln!("[INFO] Collection completed with {} collected files", count);
            },
            Err(e) => dprintln!("[ERROR] Problem to process the folder: {:?}", e),
        }

        Ok(())
    }
}
