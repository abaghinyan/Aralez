//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//
use reqwest::blocking::get;
use std::env;
use std::fs::{self, File};
use std::io::{self, Write, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use winres::WindowsResource;
use zip::ZipArchive;

#[derive(Debug, PartialEq)]
pub enum Arch {
    X86,
    X86_64,
}

fn main() -> io::Result<()> {
    // Get the CONFIG_FILE environment variable, or default to default_config
    let config_filename = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.yml".to_string());
    let config_path = Path::new("config").join(&config_filename);

    let target_config = Path::new("config").join(".config.yml");

    if !config_path.exists() {
        eprintln!(
            "Error: Configuration file '{}' not found.",
            config_path.display()
        );
        std::process::exit(1);
    }

    fs::copy(&config_path, &target_config).expect("Failed to copy config file to .config.yml");

    let target = std::env::var("TARGET").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = if target.contains("x86_64") {
        Arch::X86_64
    } else if target.contains("i686") {
        Arch::X86
    } else {
        panic!("Unsupported target architecture: {}", target);
    };
    let host_os = std::env::consts::OS;

    if target_os == "windows" {
        if host_os == "linux" {
            let windres = if target.contains("x86_64") {
                "x86_64-w64-mingw32-windres"
            } else {
                "i686-w64-mingw32-windres"
            };

            let status = Command::new(windres)
                .args(&["app.rc", "-O", "coff", "-o", "app.res"])
                .status()
                .expect("Failed to run windres");

            if !status.success() {
                eprintln!("Error: windres failed with exit code {}", status);
                std::process::exit(1);
            }

            println!("cargo:rustc-link-arg-bin=aralez=app.res");
        } else if host_os == "windows" {
            let mut res = WindowsResource::new();
            res.set_manifest_file("app.manifest");
            res.set_icon("assets/aralez.ico").compile()?;

            if let Err(e) = res.compile() {
                eprintln!("Failed to compile Windows resources: {}", e);
                std::process::exit(1);
            }
        }
    }

    let tools_dir = Path::new("tools");

    if !tools_dir.exists() {
        fs::create_dir_all(tools_dir).expect("Failed to create tools directory");
    }

    let (tools, exe_files) = populate_tools_and_files(&target_arch);

    // Remove incompatible files for executables
    let incompatible_arch = if target_arch == Arch::X86_64 { Arch::X86 } else { Arch::X86_64 };
    remove_incompatible_files(&exe_files, tools_dir, &incompatible_arch);

    // Remove incompatible files for tools
    remove_incompatible_files(&tools, tools_dir, &incompatible_arch);

    for (url, file_name) in tools {
        let file_path = tools_dir.join(file_name);
        if !file_path.exists() {
            match download_file(url, &file_path) {
                Ok(_) => println!("Downloaded {} successfully.", file_name),
                Err(e) => {
                    eprintln!("Error downloading {}: {}", file_name, e);
                    println!("Offline mode: Skipping download for {}", file_name);
                }
            }
        } else {
            println!("File {} already exists, skipping download.", file_name);
        }
    }

    if let Err(e) = extract_sysinternals(&tools_dir, &exe_files) {
        eprintln!("Error extracting Sysinternals tools: {}", e);
    }

    println!("cargo:rerun-if-changed=NULL");
    println!("cargo:rerun-if-env-changed=CONFIG_FILE");
    println!("cargo:rerun-if-changed=config");

    Ok(())
}

fn populate_tools_and_files(target_arch: &Arch) -> (Vec<(&'static str, &'static str)>, Vec<(&'static str, &'static str)>) {
    match target_arch {
        Arch::X86_64 => (
            vec![
                ("https://download.sysinternals.com/files/SysinternalsSuite.zip", "SysinternalsSuite.zip"),
                ("https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe", "winpmem_mini_rc2.exe"),
            ],
            vec![
                ("autorunsc64.exe", "autorunsc.exe"),
                ("handle64.exe", "handle.exe"),
                ("Listdlls64.exe", "Listdlls.exe"),
                ("pipelist64.exe", "pipelist.exe"),
                ("pslist64.exe", "pslist.exe"),
                ("PsService64.exe", "PsService.exe"),
                ("tcpvcon64.exe", "tcpvcon.exe"),
            ],
        ),
        Arch::X86 => (
            vec![
                ("https://download.sysinternals.com/files/SysinternalsSuite.zip", "SysinternalsSuite.zip"),
                ("https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x86.exe", "winpmem_mini_rc2.exe"),
            ],
            vec![
                ("autorunsc.exe", "autorunsc.exe"),
                ("handle.exe", "handle.exe"),
                ("Listdlls.exe", "Listdlls.exe"),
                ("pipelist.exe", "pipelist.exe"),
                ("pslist.exe", "pslist.exe"),
                ("PsService.exe", "PsService.exe"),
                ("tcpvcon.exe", "tcpvcon.exe"),
            ],
        )
    }
}

fn remove_incompatible_files(
    files: &[(&str, &str)],
    tools_dir: &Path,
    incompatible_arch: &Arch,
) {
    for (_, out_file_name) in files {
        let file_path = tools_dir.join(out_file_name);
        if file_path.exists() {
            match check_binary_arch(&file_path) {
                Ok(file_arch) => {
                    if file_arch == *incompatible_arch {
                        if let Err(e) = fs::remove_file(&file_path) {
                            eprintln!("Failed to remove file {}: {}", file_path.to_string_lossy(), e);
                        } else {
                            println!("Removed incompatible file: {}", file_path.to_string_lossy());
                        }
                    }
                }
                Err(e) => eprintln!(
                    "Error checking the architecture of the file {}: {}",
                    file_path.to_string_lossy(),
                    e
                ),
            }
        }
    }
}

fn download_file(url: &str, destination: &Path) -> Result<(), String> {
    match get(url) {
        Ok(response) => {
            if response.status().is_success() {
                let content = response.bytes().map_err(|e| e.to_string())?;
                let mut file = File::create(destination).map_err(|e| e.to_string())?;
                file.write_all(&content).map_err(|e| e.to_string())?;
                Ok(())
            } else {
                Err(format!("HTTP error: {}", response.status()))
            }
        }
        Err(e) => {
            println!("cargo:warning=Faild to connect to the internet. External tools could not be updated.");
            Err(format!("Failed to connect: {}", e))
        },
    }
}

fn extract_sysinternals(tools_dir: &Path, exe_files: &Vec<(&str, &str)>) -> io::Result<()> {
    let zip_file_path = tools_dir.join("SysinternalsSuite.zip");
    if !zip_file_path.exists() {
        println!("SysinternalsSuite.zip not found, skipping extraction.");
        return Ok(());
    }

    let zip_file = File::open(&zip_file_path)?;
    let mut archive = ZipArchive::new(zip_file)?;

    for (in_file_name, out_file_name) in exe_files {
        let mut file = match archive.by_name(in_file_name) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let out_path = tools_dir.join(out_file_name);
        if !out_path.exists() {
            let mut out_file = File::create(&out_path)?;
            io::copy(&mut file, &mut out_file)?;
            println!("Extracted {} to {:?}", in_file_name, out_path);
        }
    }

    if fs::metadata(&zip_file_path).is_ok() {
        fs::remove_file(&zip_file_path).expect("Failed to remove the ZIP file");
    }

    Ok(())
}

pub fn check_binary_arch(file_path: &Path) -> Result<Arch, String> {
    const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0" signature in little endian

    let mut file = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut buffer = [0u8; 64]; // Buffer to read the PE header

    // Read the first 64 bytes
    file.read_exact(&mut buffer).map_err(|e| format!("Failed to read file: {}", e))?;

    // Validate that it's a PE file by checking the "PE" signature
    let pe_header_offset = u32::from_le_bytes(buffer[0x3C..0x40].try_into().unwrap()); // e_lfanew
    file.seek(SeekFrom::Start(pe_header_offset as u64))
        .map_err(|e| format!("Failed to seek in file: {}", e))?;

    file.read_exact(&mut buffer[..24])
        .map_err(|e| format!("Failed to read PE header: {}", e))?;

    let pe_signature = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    if pe_signature != PE_SIGNATURE {
        return Err("Invalid PE signature".to_string());
    }

    // Machine type is at offset 4 of the PE header
    let machine = u16::from_le_bytes(buffer[4..6].try_into().unwrap());
    match machine {
        0x8664 => Ok(Arch::X86_64), // IMAGE_FILE_MACHINE_AMD64
        0x014C => Ok(Arch::X86),    // IMAGE_FILE_MACHINE_I386
        _ => Err(format!("Unknown Arch: 0x{:04X}", machine)),
    }
}
