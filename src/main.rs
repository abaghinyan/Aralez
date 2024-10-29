// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

#[macro_use]
mod macros;

mod config;
mod execute;
mod ntfs_reader;
mod sector_reader;
mod utils;

use anyhow::Result;
use clap::Parser;
use clap::{Arg, Command};
use config::Config;
use execute::run_external;
use execute::run_system;
use execute::{get_bin, run_internal};
use indicatif::{ProgressBar, ProgressStyle};
use ntfs_reader::{process_all_drives, process_drive_artifacts};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::io::{Seek, SeekFrom};
use std::path::Path;
use utils::{ensure_directory_exists, remove_dir_all};
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

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
    new_exe_file.write_all(config::CONFIG_MARKER_START)?;
    new_exe_file.write_all(&new_config_data)?;
    new_exe_file.write_all(config::CONFIG_MARKER_END)?;

    println!(
        "New executable with updated config created at: {}",
        output_exe_path
    );

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

    let config = Config::load()?;

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

    config.save(root_output)?;

    dprintln!("Aralez version: {}", env!("CARGO_PKG_VERSION"));

    // Create a spinner
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["-", "\\", "|", "/"])
            .template("{spinner:.green} {msg}")?,
    );

    spinner.set_message("Starting tasks...");

    let sorted_tasks = config.get_tasks();
    for (section_name, mut section_config) in sorted_tasks {
        if let Some(disabled_task) = section_config.disabled {
            if disabled_task {
                continue;
            }
        }
        dprintln!("[INFO] START TASK {}", section_name);
        spinner.set_message(format!("Processing: {} task", section_name));
        match section_config.r#type {
            config::TypeTasks::Collect => {
                let drive: String = section_config
                    .drive
                    .clone()
                    .unwrap_or_else(|| "C".to_string());
                spinner.set_message(format!("Processing: {} drive", drive));

                if drive == "*" {
                    process_all_drives(&mut section_config, root_output)?;
                } else {
                    process_drive_artifacts(&drive, &mut section_config, root_output)?;
                }
            }
            config::TypeTasks::Execute => {
                let _ = &section_config
                    .entries
                    .par_iter()
                    .for_each(|(_, executors)| {
                        executors.par_iter().for_each(|executor_iter| {
                            let executor = executor_iter.clone();
                            match executor.exec_type {
                                Some(exec_type) => {
                                    let output_path = format!("{}\\{}", root_output, "tools"); // Adjust the path as necessary
                                    ensure_directory_exists(&output_path)
                                        .expect("Failed to create or access output directory");

                                    let args: Vec<&str> = match executor.args {
                                        Some(ref args_array) => {
                                            args_array.iter().map(String::as_str).collect()
                                        } // Collect into Vec
                                        None => Vec::new(), // Empty Vec if no args
                                    };

                                    match exec_type {
                                        config::TypeExec::External => {
                                            let executor_name =
                                                executor.name.clone().expect(MSG_ERROR_CONFIG);
                                            spinner.set_message(format!(
                                                "Processing: {} tool",
                                                executor_name
                                            ));
                                            match get_bin(executor_name) {
                                                Ok(bin) => {
                                                    run_external(
                                                        bin,
                                                        &executor
                                                            .name
                                                            .clone()
                                                            .expect(MSG_ERROR_CONFIG)
                                                            .as_str(),
                                                        &output_path,
                                                        &executor
                                                            .output_file
                                                            .expect(MSG_ERROR_CONFIG)
                                                            .as_str(),
                                                        &args,
                                                    );
                                                }
                                                Err(e) => dprintln!("{}", e),
                                            }
                                        }
                                        config::TypeExec::Internal => {
                                            let filename =
                                                executor.output_file.expect(MSG_ERROR_CONFIG);
                                            let tool_name = executor.name.expect(MSG_ERROR_CONFIG);
                                            spinner.set_message(format!(
                                                "Processing: {} tool",
                                                tool_name
                                            ));
                                            run_internal(&tool_name, &filename, &output_path);
                                        }
                                        config::TypeExec::System => {
                                            let executor_name =
                                                executor.name.expect(MSG_ERROR_CONFIG);
                                            spinner.set_message(format!(
                                                "Processing: {} tool",
                                                executor_name
                                            ));
                                            run_system(
                                                &executor_name,
                                                &args,
                                                &executor.output_file.expect(MSG_ERROR_CONFIG),
                                                &output_path,
                                            );
                                        }
                                    }
                                }
                                None => dprintln!("{}", MSG_ERROR_CONFIG),
                            }
                        });
                    });
            }
        }
    }

    dprintln!("[INFO] All tasks completed");

    // Move the logfile into the root folder
    let logfile = &format!("{}.log", root_output);
    let tmp_logfile = &format!("{}.log", ".aralez");
    if Path::new(tmp_logfile).exists() {
        if Path::new(root_output).exists() {
            let destination_file = format!("{}/{}", root_output, logfile);
            fs::rename(tmp_logfile, &destination_file)?;
        } else {
            dprintln!("[WARN] Root file not found");
        }
    } else {
        dprintln!("[WARN] The log file not found");
    }

    spinner.set_message("Running: compression");

    zip_dir(root_output)?;

    remove_dir_all(root_output)?;

    spinner.finish_with_message("Tasks completed");

    Ok(())
}

fn zip_dir(dir_name: &str) -> io::Result<()> {
    // Create a directory with the given name (if it doesn't exist)
    let dir_path = Path::new(dir_name);
    fs::create_dir_all(&dir_path)?;

    // Create a ZIP file with the same name as the directory
    let zip_file_name = format!("{}.zip", dir_name);
    let zip_file = File::create(&zip_file_name)?;

    // Initialize ZipWriter with ZIP64 enabled
    let mut zip = ZipWriter::new(zip_file);

    let options = FileOptions::<()>::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(true);

    // Add the directory to the ZIP file
    add_directory_to_zip(&mut zip, dir_path, "", &options)?;

    // Finish the zip process
    zip.finish()?;

    Ok(())
}

fn add_directory_to_zip<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    dir_path: &Path,
    parent_dir: &str,
    options: &FileOptions<()>, // Specify the correct generic parameter
) -> io::Result<()> {
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        let name = format!("{}{}", parent_dir, entry.file_name().to_string_lossy());

        if path.is_dir() {
            // If the entry is a directory, add it to the ZIP and recurse into it
            zip.add_directory(&format!("{}/", name), *options)?;
            add_directory_to_zip(zip, &path, &format!("{}/", name), options)?;
        } else {
            // If the entry is a file, add it to the ZIP
            let mut file = File::open(&path)?;
            zip.start_file(name, *options)?;
            io::copy(&mut file, zip)?;
        }
    }

    Ok(())
}
