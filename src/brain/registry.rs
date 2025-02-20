//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::collections::HashSet;
use windows_registry::{CURRENT_USER, LOCAL_MACHINE};

use crate::config::SearchConfig;

use super::path::insert_if_valid;
use super::path::remove_drive_letter;

/// Retrieves autostart registry entries from Windows registry.
pub fn get_registries_path() -> SearchConfig {
    let mut entries: HashSet<String> = HashSet::new();

    let hives: [(_, &str); 4] = [
        (LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ];

    for (hive, subkey) in hives.iter() {
        if let Ok(key) = hive.open(subkey) {
            if let Ok(value_iter) = key.values() {
                for (name, _) in value_iter {
                    if let Ok(value_str) = key.get_string(name) {
                        insert_if_valid(&mut entries, &value_str);
                    }
                }
            }
        }
    }

    let entries_vec = entries.into_iter().map(|path| remove_drive_letter(&path)).collect();

    SearchConfig {
        root_path: Some("\\".to_owned()),
        name: None,
        output_file: None,
        args: None,
        objects: Some(entries_vec),
        encrypt: None,
        r#type: None,
        exec_type: None,
        max_size: Some(10000000),
    }
}
