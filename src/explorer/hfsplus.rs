//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//

use crate::reader::fs::*;
use crate::reader::hfsplus::{initialize_hfsplus, process_directory};
use crate::reader::sector::SectorReader;
use crate::stream::OutputTarget;
use std::io::BufReader;
use std::collections::HashSet;
use std::fs::File;
use anyhow::Result;
use super::fs::FileSystemExplorer;

pub struct HfsPlusExplorer {
    fs_reader: Option<BufReader<SectorReader<File>>>,
}

impl HfsPlusExplorer {
    pub fn new() -> Self {
        HfsPlusExplorer {
            fs_reader: None,
        }
    }
}

impl FileSystemExplorer for HfsPlusExplorer {
    fn initialize(&mut self, path: &str) -> Result<()> {
        let file = File::open(path)?;
        let sr = SectorReader::new(file, 4096)?;
        let fs_reader = BufReader::new(sr);

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

        let ctx = initialize_hfsplus(fs_reader)?;
        
        match process_directory(
            fs_reader,
            &ctx,
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
                dprintln!("[INFO] Collection completed with {} collected files (HFS+)", count);
            },
            Err(e) => dprintln!("[ERROR] Problem to process the folder log: {:?}", e),
        }

        Ok(())
    }
}
