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
mod execute;
mod ntfs_reader;
mod sector_reader;
mod utils;

use crate::command_info::CommandInfo;
use anyhow::Result;
use clap::Parser;
use clap::{Arg, Command};
use config::{Config, SearchConfig, TypeConfig};
use execute::{get_bin, run_internal};
use execute::run_external;
use execute::run_system;
use indicatif::{ProgressBar, ProgressStyle};
use ntfs_reader::list_ntfs_drives;
use sector_reader::SectorReader;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::BufReader;
use std::io::{self, Write};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use utils::ensure_directory_exists;
use utils::remove_dir_all;
use zip::{write::FileOptions, ZipWriter};

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

const MSG_ERROR_CONFIG: &str = "[ERROR] Config error";

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
            return Ok(config_string.into_owned());
        }
    }

    Err(anyhow::anyhow!(
        "Embedded configuration not found or the config file is not valid"
    ))
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

    println!(
        "New executable with updated config created at: {}",
        output_exe_path
    );

    Ok(())
}

// Helper function to find the marker in the binary data
fn find_marker(data: &[u8], marker: &[u8]) -> Option<usize> {
    data.windows(marker.len())
        .rposition(|window| window == marker) // rposition finds the last occurrence
}

fn save_config_to_file(config: &Config, output_dir: &str) -> std::io::Result<()> {
    let yaml_string = serde_yaml::to_string(&config).expect("Failed to serialize config to YAML");

    // Ensure the root_output folder exists
    let path = Path::new(output_dir);
    if !path.exists() {
        fs::create_dir_all(path)?;
    }

    // Define the output file path
    let config_file_path = path.join("config.yaml");

    // Write the YAML string to the file
    let mut file = fs::File::create(config_file_path)?;
    file.write_all(yaml_string.as_bytes())?;
    Ok(())
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
            return Err(anyhow::anyhow!(
                "Output file name is required when changing configuration"
            ));
        }
        return Ok(());
    }

    // Load configuration: Try to load the embedded configuration first, then fallback to default
    let config_data = load_embedded_config()?;
    let config: Config = match serde_yaml::from_str(&config_data) {
        Ok(config) => config,
        Err(_e) => Config::load_from_embedded()?,
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

    let root_output = &config.get_output_filename();
    
    save_config_to_file(&config, root_output)?;

    dprintln!("Aralez version: {}", env!("CARGO_PKG_VERSION"));

    // Open the NTFS disk image or partition (replace with the correct path)
    let f = File::open("\\\\.\\C:")?;
    let sr = SectorReader::new(f, 4096)?;
    let mut fs = BufReader::new(sr);
    let ntfs = ntfs_reader::initialize_ntfs(&mut fs)?;

    // Initialize the command state with the root directory
    let mut info = ntfs_reader::initialize_command_info(fs, &ntfs)?;

    // Create a progress bar based on the total number of tasks
    let pb = ProgressBar::new(config.tasks_entries_len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - {msg}",
        )?
        .progress_chars("#>-"),
    );

    let sorted_tasks = config.get_tasks();

    for (section_name, mut section_config) in sorted_tasks {
        dprintln!("[INFO] START TASK {}",section_name);
        match section_config.r#type {
            config::TypeTasks::Collect => {
                let mut processed_paths = HashSet::new();

                for (_, artifacts) in &mut section_config.entries {
                    for mut artifact in artifacts {
                        let path_key = format!(
                            "{}\\{:?}",
                            artifact.get_expanded_dir_path(),
                            artifact.objects.clone().unwrap_or_default()
                        );

                        if !processed_paths.contains(&path_key) {
                            search_in_config(&mut info, &mut artifact, root_output)?;
                            pb.inc(1); // Increment the progress bar
                            pb.set_message(format!("[INFO] Running {}", path_key));

                            // Mark the path as processed
                            processed_paths.insert(path_key);
                        }
                    }
                }
            }
            config::TypeTasks::Execute => {
                for (_, executors) in &section_config.entries {
                    for executor in executors.clone() {
                        match executor.exec_type {
                            Some(exec_type) => {
                                let output_path = format!("{}\\{}", root_output, "tools"); // Adjust the path as necessary
                                ensure_directory_exists(&output_path)
                                    .expect("Failed to create or access output directory");

                                let args: &[&str] = match executor.args {
                                    Some(ref args_array) => {
                                        &args_array.iter().map(String::as_str).collect::<Vec<_>>()[..]
                                    }
                                    None => &[],
                                };

                                match exec_type {
                                    config::TypeExec::External => {
                                        pb.inc(1); // Increment the progress bar
                                        pb.set_message(format!(
                                            "[INFO] Running: {} tool",
                                            executor.name.clone().expect(MSG_ERROR_CONFIG)
                                        ));
                                        run_external(
                                            get_bin(executor.name.clone().expect(MSG_ERROR_CONFIG))?,
                                            &executor
                                                .name
                                                .clone()
                                                .expect(MSG_ERROR_CONFIG)
                                                .as_str(),
                                            &output_path,
                                            &executor.output_file.expect(MSG_ERROR_CONFIG).as_str(),
                                            &args,
                                        );
                                    }
                                    config::TypeExec::Internal => {
                                        let filename = executor.output_file.expect(MSG_ERROR_CONFIG);
                                        let tool_name = executor.name.expect(MSG_ERROR_CONFIG);
                                        pb.inc(1); // Increment the progress bar
                                        pb.set_message(format!(
                                            "[INFO] Running {} tool",
                                            tool_name
                                        ));
                                        run_internal(&tool_name, &filename, &output_path);
                                    }
                                    config::TypeExec::System => {
                                        pb.inc(1); // Increment the progress bar
                                        pb.set_message(format!(
                                            "[INFO] Running: {} tool",
                                            executor.name.clone().expect(MSG_ERROR_CONFIG)
                                        ));
                                        run_system(
                                            &executor.name.clone().expect(MSG_ERROR_CONFIG),
                                            &args,
                                            &executor.output_file.expect(MSG_ERROR_CONFIG),
                                            &output_path,
                                        );
                                    }
                                }
                            }
                            None => dprintln!("{}", MSG_ERROR_CONFIG),
                        }
                    }
                }
            }
        }
    }

    let ntfs_drives = list_ntfs_drives()?;
    // Loop through each NTFS drive and process, skipping the C drive
    for drive in ntfs_drives {
        // Skip C drive since you process it separately
        if drive.starts_with("C:") {
            continue;
        }
        dprintln!("[INFO] Running drive: {}", drive);
        let drive_letter = match drive.chars().next() {
            Some(l) => l,
            None => continue,
        };
        let output_path = format!("{}\\{}", root_output, drive_letter);

        ensure_directory_exists(&output_path)?;

        let f = File::open(format!("\\\\.\\{}:", drive_letter))?;
        let sr = SectorReader::new(f, 4096)?; // Adjust sector size if needed
        let mut fs = BufReader::new(sr);

        // Initialize NTFS and process the MFT
        if let Ok(ntfs) = ntfs_reader::initialize_ntfs(&mut fs) {
            let mut info = ntfs_reader::initialize_command_info(fs, &ntfs)?;

            // Prepare search configuration to target the MFT file
            let mut search_config = SearchConfig {
                dir_path: Some("".to_string()),
                objects: Some(vec!["$MFT".to_string()]),
                max_size: None,
                encrypt: None,
                r#type: Some(TypeConfig::String),
                name: None,
                output_file: None,
                exec_type: None,
                args: None,
            };
            match search_config.sanitize() {
                Ok(_) => ntfs_reader::find_files_in_dir(&mut info, &mut search_config, &output_path)?,
                Err(_) => dprintln!("[ERROR] Config sanitization failed"),
            };
        } else {
            dprintln!(
                "Drive {} is not an NTFS file system or cannot be read.",
                drive
            );
        }
    }

    dprintln!("Tasks completed");

    // Move the logfile into the root folder
    let logfile = "aralez.log";
    if Path::new(logfile).exists() {
        if Path::new(root_output).exists() {
            let destination_file = format!("{}/{}", root_output, logfile);
            fs::rename(logfile, &destination_file)?;
        } else {
            dprintln!("[WARN] Root file not found");
        }
    } else {
        dprintln!("[WARN] The log file not found");
    }

    zip_dir(root_output)?;

    remove_dir_all(root_output)?;

    pb.finish_with_message("[INFO] Collect complete!");

    Ok(())
}

fn search_in_config<T>(
    info: &mut CommandInfo<T>,
    config: &mut SearchConfig,
    root_output: &str,
) -> Result<()>
where
    T: Read + Seek,
{
    
    config.sanitize().expect("[ERROR] Config sanitization failed");
    let drive = format!("{}\\{}", root_output.to_string(), "C");
    ntfs_reader::find_files_in_dir(
        info,
        config,
        &format!("{}\\{}", drive, &config.get_expanded_dir_path()),
    )
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
