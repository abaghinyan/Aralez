use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use reqwest::blocking::get;
use zip::ZipArchive;
use std::process::Command;
use winres::WindowsResource;

fn main() -> io::Result<()> {
    // Get the filename from the CONFIG_FILE environment variable, or default to "config.yml"
    let config_filename = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.yml".to_string());
    let config_path = Path::new("config").join(&config_filename);

    // Check if the specified configuration file exists
    if !config_path.exists() {
        eprintln!(
            "Error: Configuration file '{}' not found in the 'config' folder.",
            config_filename
        );
        std::process::exit(1); // Exit with an error code
    }

    let target = std::env::var("TARGET").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let host_os = std::env::consts::OS;

    if target_os == "windows" {
        if host_os == "linux" {
            // Use the appropriate windres for 32-bit or 64-bit Windows targets
            let windres = if target.contains("x86_64") {
                "x86_64-w64-mingw32-windres"
            } else {
                "i686-w64-mingw32-windres"
            };
    
            // Compile the .rc file into a .res file using the selected windres
            let status = Command::new(windres)
                .args(&["app.rc", "-O", "coff", "-o", "app.res"])
                .status()
                .expect("Failed to run windres");
    
            if !status.success() {
                eprintln!("Error: windres failed with exit code {}", status);
                std::process::exit(1);
            }
    
            // Link the .res file into the final binary
            println!("cargo:rustc-link-arg-bin=aralez=app.res");
        } else if host_os == "windows" {
            let mut res = WindowsResource::new();
        
            // Set the manifest directly as a string
            res.set_manifest_file("app.manifest");
            res.set_icon("assets/aralez.ico")
            .compile()?;

            if let Err(e) = res.compile() {
                eprintln!("Failed to compile Windows resources: {}", e);
                std::process::exit(1);
            }
        }
    }
    

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
        "pipelist.exe",
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

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CONFIG_FILE");

    Ok(())
}
