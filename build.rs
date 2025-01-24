use reqwest::blocking::get;
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use winres::WindowsResource;
use zip::ZipArchive;

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

    // Initialize the tools variable as mutable
    let tools: Vec<(&str, &str)>;
    let exe_files: Vec<(&str, &str)>;

    // Conditionally populate tools based on the target architecture
    if target.contains("x86_64") {
        tools = vec![
            ("https://download.sysinternals.com/files/SysinternalsSuite.zip", "SysinternalsSuite.zip"),
            ("https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe", "winpmem_mini_rc2.exe"),
        ];
        exe_files = vec![
            ("autorunsc64.exe", "autorunsc.exe"),
            ("handle64.exe", "handle.exe"),
            ("Listdlls64.exe","Listdlls.exe"),
            ("pipelist64.exe", "pipelist.exe"),
            ("pslist64.exe", "pslist.exe"),
            ("PsService64.exe", "PsService.exe"),
            ("tcpvcon64.exe", "tcpvcon.exe"),
        ];
    } else if target.contains("i686") {
        tools = vec![
            ("https://download.sysinternals.com/files/SysinternalsSuite.zip", "SysinternalsSuite.zip"),
            ("https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x86.exe", "winpmem_mini_rc2.exe"),
        ];
        exe_files = vec![
            ("autorunsc.exe", "autorunsc.exe"),
            ("handle.exe", "handle.exe"),
            ("Listdlls.exe","Listdlls.exe"),
            ("pipelist.exe", "pipelist.exe"),
            ("pslist.exe", "pslist.exe"),
            ("PsService.exe", "PsService.exe"),
            ("tcpvcon.exe", "tcpvcon.exe"),
        ];
    } else {
        panic!("Unsupported target architecture: {}", target);
    }

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

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CONFIG_FILE");
    println!("cargo:rerun-if-changed=config");

    Ok(())
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
        Err(e) => Err(format!("Failed to connect: {}", e)),
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
