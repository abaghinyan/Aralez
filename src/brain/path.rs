//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::{collections::HashSet, path::Path};
use regex::Regex;

use crate::utils::replace_env_vars;

pub fn insert_if_valid(set: &mut HashSet<String>, path: &str) {
    let cleaned_path = clean_path(&replace_env_vars(path));

    // Validate that it's an actual file path
    if is_valid_file_path(&cleaned_path) {
        set.insert(cleaned_path);
    }
}

/// Cleans a file path by removing arguments while preserving the valid executable path.
fn clean_path(path: &str) -> String {
    let path = path.trim_matches(|c| c == '"' || c == '\''); 

    let re = Regex::new(r"^(.*?\.(exe|dll|sys))").unwrap(); 

    if let Some(captured) = re.captures(path) {
        return captured.get(1).unwrap().as_str().to_string();
    }

    path.to_string() // Return original if no match
}

/// Checks if a path is a valid file path (not a directory).
fn is_valid_file_path(path: &str) -> bool {
    let p = Path::new(path);

    // Ensure the path contains a filename with an extension
    p.extension().is_some()
}

/// Removes the drive letter from a Windows path.
pub fn remove_drive_letter(path: &str) -> String {
    if path.starts_with("\\\\") {
        path.to_string()
    } else {
        let mut chars = path.chars();
        if chars.nth(1) == Some(':') {
            return format!("\\{}", path[3..].to_string()); 
        }
        path.to_string()
    }
}