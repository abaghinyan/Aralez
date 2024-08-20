use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use reqwest::blocking::get;
use zip::ZipArchive;

fn main() {
    let tools_dir = Path::new("tools");

    // Ensure the tools directory exists
    if !tools_dir.exists() {
        fs::create_dir_all(tools_dir).expect("Failed to create tools directory");
    }

    // URL of the Sysinternals Suite ZIP file
    let url = "https://download.sysinternals.com/files/SysinternalsSuite.zip";
    let zip_file_path = tools_dir.join("SysinternalsSuite.zip");

    // Download the ZIP file if it doesn't exist
    if !zip_file_path.exists() {
        println!("Downloading SysinternalsSuite.zip...");

        let response = get(url).expect("Failed to send request");
        if response.status().is_success() {
            let content = response.bytes().expect("Failed to read response bytes");
            let mut file = File::create(&zip_file_path).expect("Failed to create ZIP file");
            file.write_all(&content).expect("Failed to write ZIP file");
            println!("Downloaded SysinternalsSuite.zip successfully.");
        } else {
            panic!("Failed to download ZIP file: {}", response.status());
        }
    }

    // Extract specific .exe files from the ZIP
    let exe_files = vec![
        "autorunsc.exe",
        "handle.exe",
        "Listdlls.exe",
        "pslist.exe",
        "PsService.exe",
        "tcpvcon.exe",
    ];

    let zip_file = File::open(&zip_file_path).expect("Failed to open ZIP file");
    let mut archive = ZipArchive::new(zip_file).expect("Failed to read ZIP archive");

    for file_name in exe_files {
        let mut file = archive
            .by_name(file_name)
            .expect(&format!("File {} not found in the archive", file_name));

        let out_path = tools_dir.join(file_name);
        if !out_path.exists() {
            let mut out_file = File::create(&out_path).expect("Failed to create output file");
            io::copy(&mut file, &mut out_file).expect("Failed to extract file");
            println!("Extracted {} to {:?}", file_name, out_path);
        }
    }

    // Remove the ZIP file after extraction
    if zip_file_path.exists() {
        fs::remove_file(&zip_file_path).expect("Failed to remove the ZIP file");
        println!("Removed the ZIP file: {:?}", zip_file_path);
    }

    // This tells Cargo to re-run this script if the build.rs script itself changes.
    println!("cargo:rerun-if-changed=build.rs");
}
