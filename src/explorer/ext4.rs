//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Razmik Arshakyan
//

use crate::reader::{ext4::process_directory, fs::*};
use std::collections::HashSet;
use anyhow::Result;
use std::path::{Path, PathBuf};
use ext4_view::Ext4;

use super::fs::FileSystemExplorer;

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
        let ext4_parser = self.parser.as_ref().ok_or_else(|| std::io::Error::new
            (std::io::ErrorKind::Other, "ext4_parser not initialized"))?;
        let path = Path::new("/");
        let mut visited = HashSet::new();
        let mut count = 0;
        let dest: &Path = Path::new(&dest_folder);
        process_directory(ext4_parser, path, config_tree,
            &dest, &mut visited, &mut count)?;
        dprintln!("Finished processing of drive {}", drive);
        Ok(())
    }
}

