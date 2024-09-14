//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

#[macro_use]
mod macros;

mod command_info;
mod config;
mod embin;
mod network_info;
mod ntfs_reader;
mod process;
mod process_details;
mod sector_reader;
mod tool_runner;
mod utils;

use crate::command_info::CommandInfo;
use crate::tool_runner::run_tool;
use ntfs_reader::list_ntfs_drives;
use anyhow::Result;
use clap::Parser;
use clap::{Arg, Command};
use config::{Config, SearchConfig};
use embin::execute;
use hostname::get;
use indicatif::{ProgressBar, ProgressStyle};
use sector_reader::SectorReader;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::BufReader;
use std::io::{self, Write};
use std::io::{Read, Seek, SeekFrom};
use utils::ensure_directory_exists;
use zip::{write::FileOptions, ZipWriter};
use std::path::Path;

const CONFIG_MARKER_START: &[u8] = b"# CONFIG_START"; 
const CONFIG_MARKER_END: &[u8] = b"# CONFIG_END"; 

#[derive(Parser)]
struct Cli {
    /// Activate debug mode even in release builds
    #[arg(long)]
    debug: bool,

    /// Show the configuration file and exit
    #[arg(long)]
    show_config: bool,
}
const HELP_TEMPLATE: &str = "{bin} {version}
{author}

{about}

USAGE:
    {usage}

{all-args}
";

// Helper function to pretty-print the configuration
fn show_config(config: &Config) -> Result<()> {
    let serialized = serde_yaml::to_string(config)?;
    println!("{}", serialized);
    Ok(())
}

// Function to load the embedded configuration at runtime
fn load_embedded_config() -> Result<String> {
    let current_exe = env::current_exe()?;
    let mut file = File::open(current_exe)?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if let Some(start) = find_marker(&buffer, CONFIG_MARKER_START) {
        if let Some(end) = find_marker(&buffer[start..], CONFIG_MARKER_END) {
            let config_data = &buffer[start + CONFIG_MARKER_START.len()..start + end];
            let config_string = String::from_utf8_lossy(config_data);
            return  Ok(config_string.into_owned());
        }
    }
    
    Err(anyhow::anyhow!("Embedded configuration not found or the config file is not valid"))
}

// Function to update the embedded configuration
fn update_embedded_config(new_config_path: &str, output_exe_path: &str) -> std::io::Result<()> {
    let new_config_data = fs::read(new_config_path)?;

    // Path to the current executable
    let current_exe = env::current_exe().expect("Failed to get current executable path");

    // Copy the current executable to the specified output file
    fs::copy(&current_exe, &output_exe_path)?;

    // Open the copied executable file for reading and writing
    let mut new_exe_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&output_exe_path)?;

    // Append the config marker and new config data at the end of the file
    new_exe_file.seek(SeekFrom::End(0))?;
    new_exe_file.write_all(CONFIG_MARKER_START)?;
    new_exe_file.write_all(&new_config_data)?;
    new_exe_file.write_all(CONFIG_MARKER_END)?;

    println!("New executable with updated config created at: {}", output_exe_path);

    Ok(())
}

// Helper function to find the marker in the binary data
fn find_marker(data: &[u8], marker: &[u8]) -> Option<usize> {
    data.windows(marker.len())
        .rposition(|window| window == marker) // rposition finds the last occurrence
}
fn main() -> Result<()> {
    // Print the welcome message
    println!(
        "Welcome to {} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    println!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!("Developed by: {}", env!("CARGO_PKG_AUTHORS"));
    println!();

    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("Activate debug mode")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show_config")
                .long("show_config")
                .help("Show the configuration file and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("change_config")
                .long("change_config")
                .help("Change the embedded configuration file")
                .value_name("CONFIG_FILE")
                .value_hint(clap::ValueHint::FilePath)
                .required(false),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Specify the output executable file name when changing the embedded configuration")
                .value_name("OUTPUT_FILE")
                .value_hint(clap::ValueHint::FilePath)
                .requires("change_config")
                .required(false),
        )
        .help_template(HELP_TEMPLATE)
        .get_matches();

    // Handle changing the embedded configuration
    if let Some(config_path) = matches.get_one::<String>("change_config") {
        if let Some(output_path) = matches.get_one::<String>("output") {
            update_embedded_config(config_path, output_path)?;
        } else {
            return Err(anyhow::anyhow!("Output file name is required when changing configuration"));
        }
        return Ok(());
    }
    
    // Load configuration: Try to load the embedded configuration first, then fallback to default
    let config_data = load_embedded_config()?;
    let config: Config = match serde_yaml::from_str(&config_data) {
        Ok(config) => config,
        Err(_e) =>  Config::load_from_embedded()?
    };

    // Handle show_config flag
    if matches.get_flag("show_config") {
        return show_config(&config);
    }

    // Check if the --debug flag was provided
    if matches.get_flag("debug") {
        env::set_var("DEBUG_MODE", "true");
        println!("Debug mode activated!");
    }
    let machine_name = get()
        .ok()
        .and_then(|hostname| hostname.into_string().ok())
        .unwrap_or_else(|| "machine".to_string());

    let root_output = &machine_name;

    let ntfs_drives = list_ntfs_drives()?;
    // Loop through each NTFS drive and process, skipping the C drive
    for drive in ntfs_drives {
        // Skip C drive since you process it separately
        if drive.starts_with("C:") {
            continue;
        }
        dprintln!("Processing drive: {}", drive);
        let drive_letter = match drive.chars().next() {
            Some(l) => l,
            None => continue  
        };
        let output_path = format!("{}\\{}", root_output, drive_letter);

        ensure_directory_exists(&output_path)?; 

        let f = File::open(format!("\\\\.\\{}:",drive_letter))?;
        let sr = SectorReader::new(f, 4096)?; // Adjust sector size if needed
        let mut fs = BufReader::new(sr);

        // Initialize NTFS and process the MFT
        if let Ok(ntfs) = ntfs_reader::initialize_ntfs(&mut fs) {
            let mut info = ntfs_reader::initialize_command_info(fs, &ntfs)?;

            // Prepare search configuration to target the MFT file
            let search_config = SearchConfig {
                dir_path: "".to_string(), // Root directory to find $MFT
                extensions: Some(vec!["$MFT".to_string()]), // Look for $MFT
                max_size: None, // No size limit for the MFT
                encrypt: None, // You can add encryption here if needed
            };

            // Use find_files_in_dir to process the $MFT file for each drive
            ntfs_reader::find_files_in_dir(&mut info, &search_config, &output_path)?;
        } else {
            dprintln!("Drive {} is not an NTFS file system or cannot be read.", drive);
        }
    }
    // Open the NTFS disk image or partition (replace with the correct path)
    let f = File::open("\\\\.\\C:")?;
    let sr = SectorReader::new(f, 4096)?;
    let mut fs = BufReader::new(sr);
    let ntfs = ntfs_reader::initialize_ntfs(&mut fs)?;

    // Initialize the command state with the root directory
    let mut info = ntfs_reader::initialize_command_info(fs, &ntfs)?;

    // Get users from NTFS
    let users = ntfs_reader::get_users(&mut info)?;

    // Consolidate all user-specific configurations into a single list
    let consolidated_configs = expand_configs_for_all_users(&config, &users);

    // Create a progress bar based on the total number of tasks
    let pb = ProgressBar::new(consolidated_configs.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - {msg}",
        )?
        .progress_chars("#>-"),
    );

    // Tools

    let output_path = format!("{}\\{}", root_output, "tools"); // Adjust the path as necessary
    ensure_directory_exists(&output_path).expect("Failed to create or access output directory");

    // Iterate over tools from config
    for tool in &config.tools {
        let exe_bytes: &[u8] = match tool.name.as_str() {
            "autorunsc.exe" => include_bytes!("../tools/autorunsc.exe"),
            "handle.exe" => include_bytes!("../tools/handle.exe"),
            "tcpvcon.exe" => include_bytes!("../tools/tcpvcon.exe"),
            "pslist.exe" => include_bytes!("../tools/pslist.exe"),
            "Listdlls.exe" => include_bytes!("../tools/Listdlls.exe"),
            "PsService.exe" => include_bytes!("../tools/PsService.exe"),
            _ => return Err(anyhow::anyhow!("Tool not found")),
        };

        let args: Vec<&str> = tool.args.iter().map(String::as_str).collect();
        execute(exe_bytes, &tool.name, &output_path, &tool.output_file.as_str(),&args)?;
    }

    // Iterate over win_tools from config
    for tool in &config.win_tools {
        let args: Vec<&str> = tool.args.iter().map(String::as_str).collect();
        match run_tool(&tool.name, &args, &tool.output_file, &output_path) {
            Ok(_) => {
                pb.inc(1); // Increment the progress bar
                pb.set_message(format!("Processing: {} tool", tool.name));
            }
            Err(e) => dprintln!("Error running {}: {}", tool.name, e),
        }
    }

    let path = Path::new(&output_path);

    // Processes info
    let filename = "ProcInfo.txt";
    if let Err(e) = process::run_ps(filename, &path) {
        dprintln!("Error: {}", e);
    } else {
        pb.inc(1); // Increment the progress bar
        pb.set_message(format!("Processing: {} tool", "ProcInfo"));
    }

    // Process details
    let filename = "ProcDetailsInfo.txt";
    if let Err(e) = process_details::run(&filename, &path) {
        dprintln!("Error: {}", e);
    } else {
        pb.inc(1); // Increment the progress bar
        pb.set_message(format!("Processing: {} tool", "ProcDetailsInfo"));
    }

    // Network info
    let filename = "PortsInfo.txt";

    if let Err(e) = network_info::run_network_info(filename, &path) {
        dprintln!("Error writing network info: {}", e);
    } else {
        pb.inc(1); // Increment the progress bar
        pb.set_message(format!("Processing: {} tool", "NetworkInfo (PortsInfo)"));
    }

    // Get Files

    // Track already processed paths
    let mut processed_paths = HashSet::new();

    // Process each consolidated configuration
    for (user, search_config) in consolidated_configs {
        let path_key = format!(
            "{}\\{:?}",
            search_config.dir_path,
            search_config.extensions.clone().unwrap_or_default()
        );

        // Skip processing if this path has already been processed
        if !processed_paths.contains(&path_key) {
            search_in_config(&mut info, &search_config, root_output)?;
            pb.inc(1); // Increment the progress bar
            pb.set_message(format!("Processing: {} for user {}", path_key, user));

            // Mark the path as processed
            processed_paths.insert(path_key);
        }
    }

    zip_dir(root_output)?;
    pb.finish_with_message("Collect complete!");

    Ok(())
}

// Function to expand the configuration for all users and consolidate them
fn expand_configs_for_all_users(config: &Config, users: &[String]) -> Vec<(String, SearchConfig)> {
    let mut consolidated_configs = Vec::new();

    for user in users {
        let mut variables = HashMap::new();
        variables.insert("user".to_string(), user.clone());

        let user_specific_config = config.expand_placeholders(&variables);

        for (_key, configs) in &user_specific_config.entries {
            for config in configs {
                consolidated_configs.push((user.clone(), config.clone()));
            }
        }
    }

    consolidated_configs
}

fn search_in_config<T>(
    info: &mut CommandInfo<T>,
    config: &SearchConfig,
    root_output: &str,
) -> Result<()>
where
    T: Read + Seek,
{
    let drive = format!("{}\\{}", root_output.to_string(), "C");
    ntfs_reader::find_files_in_dir(info, config, &format!("{}\\{}", drive, &config.dir_path))
}

fn zip_dir(dir_name: &str) -> io::Result<()> {
    // Create a directory with the given name
    let dir_path = Path::new(dir_name);
    fs::create_dir_all(&dir_path)?;

    // Create a ZIP file with the same name as the directory
    let zip_file_name = format!("{}.zip", dir_name);
    let zip_file = File::create(&zip_file_name)?;
    let mut zip = ZipWriter::new(zip_file);

    // Add the directory to the ZIP file
    add_directory_to_zip(&mut zip, dir_path, "")?;

    // Finish the zip process
    zip.finish()?;

    // Remove the directory after zipping
    fs::remove_dir_all(dir_path)?;

    Ok(())
}

fn add_directory_to_zip<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    dir_path: &Path,
    parent_dir: &str,
) -> io::Result<()> {
    // Specify the type for FileOptions
    let options = FileOptions::<()>::default().unix_permissions(0o755);

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        let name = format!("{}{}", parent_dir, entry.file_name().to_string_lossy());

        if path.is_dir() {
            // If the entry is a directory, add it to the ZIP and recurse into it
            zip.add_directory(&name, options)?;
            add_directory_to_zip(zip, &path, &format!("{}/", name))?;
        } else {
            // If the entry is a file, add it to the ZIP
            let mut file = File::open(path)?;
            zip.start_file(name, options)?;
            io::copy(&mut file, zip)?;
        }
    }

    Ok(())
}
