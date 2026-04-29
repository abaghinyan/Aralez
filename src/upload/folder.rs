// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::fs;
use std::path::Path;

/// Copy the zip file to a local or mounted network folder.
pub fn upload(zip_path: &str, dest_folder: &str) -> Result<(), anyhow::Error> {
    let dest_path = Path::new(dest_folder);

    // Create destination directory if it doesn't exist
    if !dest_path.exists() {
        fs::create_dir_all(dest_path)?;
        dprintln!("[INFO] Created output directory: {}", dest_folder);
    }

    let zip_file = Path::new(zip_path);
    let file_name = zip_file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid zip file path"))?;
    let dest_file = dest_path.join(file_name);

    fs::copy(zip_path, &dest_file)?;

    println!(
        "[INFO] Zip file copied to: {}",
        dest_file.display()
    );
    dprintln!(
        "[INFO] Zip file copied to: {}",
        dest_file.display()
    );

    Ok(())
}
