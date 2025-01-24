// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
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
mod resource;

use execute::get_list_tools;
use resource::{add_resource, list_resources, remove_resource};
use anyhow::Result;
use clap::Parser;
use clap::{Arg, Command};
use config::{Config, ExecType};
use execute::{get_bin, run, run_internal};
use indicatif::{ProgressBar, ProgressStyle};
use ntfs_reader::{process_all_drives, process_drive_artifacts};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::io::Seek;
use std::path::Path;
use utils::{ensure_directory_exists, remove_dir_all};
use zip::{write::FileOptions, CompressionMethod, ZipWriter};
use std::time::UNIX_EPOCH;
use chrono::DateTime;
use chrono::Utc;
use zip::DateTime as ZipDateTime;
use chrono::Datelike;
use chrono::Timelike;

#[derive(Parser)]
struct Cli {
    /// Activate debug mode even in release builds
    #[arg(long)]
    debug: bool,

    /// Show the configuration file and exit
    #[arg(long)]
    show_config: bool,

    /// Specify the default drive to process
    #[arg(long, default_value = "C")]
    default_drive: String,
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
fn show_config() -> Result<()> {
    let data = Config::get_raw_data()?;
    println!("{}", data);
    Ok(())
}

// Helper function to check the configuration
fn check_config() -> Result<Config, anyhow::Error> {
    Config::load()
}

/// Helper function to check if the drive exists
fn is_drive_accessible(drive: &str) -> bool {
    let drive_path = format!("{}:\\", drive);
    fs::metadata(&drive_path).is_ok()
}

fn main() -> Result<(), anyhow::Error> {
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
            Arg::new("default_drive")
                .long("default_drive")
                .help("Specify the default drive to process (default: C)")
                .value_name("DRIVE")
                .default_value("C"),
        )
        .arg(
            Arg::new("show_config")
                .long("show_config")
                .help("Show the configuration file and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("check_config")
                .long("check_config")
                .help("Check the configuration file")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("change_config")
                .long("change_config")
                .help("Change the embedded configuration file")
                .value_names(&["CONFIG_FILE", "OUTPUT_FILE"])
                .value_hint(clap::ValueHint::FilePath)
                .num_args(2)
                .required(false),
        )
        .arg(
            Arg::new("add_tool")
                .long("add_tool")
                .help("Add a new executable tool to the resources")
                .value_names(&["EXECUTABLE_TOOL_PATH", "OUTPUT_FILE"])
                .value_hint(clap::ValueHint::FilePath)
                .num_args(2)
                .required(false),
        )
        .arg(
            Arg::new("remove_tool")
                .long("remove_tool")
                .help("Remove an executable tool to the resources")
                .value_names(&["EXECUTABLE_TOOL_NAME", "OUTPUT_FILE"])
                .value_hint(clap::ValueHint::Other)
                .num_args(2)
                .required(false),
        )
        .arg(
            Arg::new("list_tools")
                .long("list_tools")
                .help("List all external tools")
                .action(clap::ArgAction::SetTrue),
        )
        .help_template(HELP_TEMPLATE)
        .get_matches();

    // Handle changing the embedded configuration
    if let Some(values) = matches.get_many::<String>("change_config") {
        let args: Vec<_> = values.collect();
        let config_path = args[0];
        let output_path = args[1];
        match Config::check_config_file(&config_path) {
            Ok(_) => {
                if !output_path.is_empty() {
                    match add_resource(config_path, "config.yml", output_path) {
                        Ok(_) => println!("[INFO] The config `{}` was successfully added to `{}`.",config_path, output_path),
                        Err(_) => println!("[ERROR] Problem to add the config {} in the resource.", config_path),
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "[ERROR] Output file name is required when changing configuration"
                    ));
                }
                return Ok(());
            },
            Err(e) => return Err(anyhow::anyhow!(e.to_string())),
        }
        
    }

    // Add new tool
    if let Some(values) = matches.get_many::<String>("add_tool") {
        let args: Vec<_> = values.collect();
        let tool_path = args[0];
        let output_path = args[1];
        if !output_path.is_empty() {
            if let Some(resource_name) = tool_path.split('\\').last() {
                if resource_name != "config.yml" {
                    match add_resource(tool_path, resource_name, output_path) {
                        Ok(_) => println!("[INFO] The tool `{}` was successfully added to `{}`.",tool_path, output_path),
                        Err(_) => println!("[ERROR] Problem to add the external tool {} in the resource.", tool_path),
                    }
                } else {
                    println!("[ERROR] The filename cant't be 'config.yml'.");
                }
            } else {
                println!("[ERROR] File {} not found.", tool_path);
            }
        } else {
            return Err(anyhow::anyhow!(
                "[ERROR] Output file name is required when adding external tool"
            ));
        }
        return Ok(());
    }

    // Remove tool
    if let Some(values) = matches.get_many::<String>("remove_tool") {
        let args: Vec<_> = values.collect();
        let tool_name = args[0];
        let output_path = args[1];
        if !output_path.is_empty() {
            match remove_resource(tool_name, output_path) {
                Ok(_) => println!("[INFO] Resource {} was removed successfully from {}.", tool_name, output_path),
                Err(_) => {
                    println!("[WARN] Tool doesn't exist or is static")
                },
            }
        } else {
            return Err(anyhow::anyhow!(
                "[ERROR] Output file name is required when adding external tool"
            ));
        }
        return Ok(());
    }

    // list all tools
    if matches.get_flag("list_tools") {
        println!("== External tools ==");
        let ext_list = get_list_tools();
        for tool in ext_list {
            println!("(static) {}",tool);
        }
        match list_resources(10) {
            Ok(list_resources_array) => {
                for resource_element in list_resources_array {
                    if resource_element != "CONFIG.YML" {
                        println!("(dynamic) {}",resource_element);
                    }
                }
            },
            Err(_) => ()
        }
        return Ok(());
    }

    // Handle show_config flag
    if matches.get_flag("show_config") {
        return show_config();
    }

    // Handle check_config flag
    if matches.get_flag("check_config") {
        return match check_config() {
            Ok(_) => {
                println!("The configuration file is valid");
                Ok(())
            },
            Err(e) => Err(e),
        };
    }

    let config = Config::load()?;

    // Check if the --debug flag was provided
    if matches.get_flag("debug") {
        env::set_var("DEBUG_MODE", "true");
        println!("Debug mode activated!");
    }

    let root_output = &config.get_output_filename();

    config.save(root_output)?;

    dprintln!("Aralez version: {}", env!("CARGO_PKG_VERSION"));
    
    #[cfg(target_pointer_width = "64")]
    dprintln!("Aralez architecture: x64 (64bit)");

    #[cfg(target_pointer_width = "32")]
    dprintln!("Aralez architecture: x86 (32bit)");

    // Create a spinner
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["-", "\\", "|", "/"])
            .template("{spinner:.green} {msg}")?,
    );

    spinner.set_message("Starting tasks...");

    // Parse the default drive
    let c_drive = "C".to_string();
    let default_drive = matches.get_one::<String>("default_drive").unwrap_or(&c_drive);

    let sorted_tasks = config.get_tasks();
    for (section_name, mut section_config) in sorted_tasks {
        if let Some(disabled_task) = section_config.disabled {
            if disabled_task {
                continue;
            }
        }
        dprintln!("[INFO] == Starting task `{}` ==", section_name);
        spinner.set_message(format!("Processing: `{}` task", section_name));
        match section_config.r#type {
            config::TypeTasks::Collect => {
                let drive: String = section_config
                    .drive
                    .clone()
                    .unwrap_or_else(|| default_drive.to_string());
                spinner.set_message(format!("Processing: `{}` drive", drive));

                if drive == "*" {
                    process_all_drives(&mut section_config, root_output)?;
                } else {
                    // Check if the drive exists
                    if !is_drive_accessible(&drive) {
                        dprintln!("[ERROR] Drive `{}` is not accessible or does not exist", drive);
                    } else {
                        process_drive_artifacts(&drive, &mut section_config, root_output)?;
                    }
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
                                    let output_path = root_output; 
                                    ensure_directory_exists(&output_path)
                                        .expect("Failed to create or access output directory");

                                    // Sanitize args
                                    let args_refs: Vec<String> = match executor.args {
                                        Some(ref args_array) => {
                                            args_array
                                                .iter()
                                                .map(|arg| {
                                                    let mut updated_arg = arg.to_string();
                                                    if  arg.contains("{{root_output_path}}") {
                                                        updated_arg = arg.replace("{{root_output_path}}", output_path);
                                                        if let Some(pos) = updated_arg.rfind('\\') {
                                                            let directory_path = &updated_arg[..pos];
                                                            ensure_directory_exists(directory_path)
                                                                .expect("Failed to create or access output directory");
                                                        }
                                                    } 
                                                    updated_arg
                                                })
                                                .collect()
                                        }
                                        None => Vec::new(),
                                    };
                                    let args: Vec<&str> = args_refs.iter().map(String::as_str).collect();

                                    // Sanitize output_file
                                    let updated_output_file = match executor.output_file {
                                        Some(output_file) => {
                                            let mut updated_output_file: String = output_file.to_string();
                                            if  output_file.contains("{{root_output_path}}") {
                                                updated_output_file = output_file.replace("{{root_output_path}}", output_path);
                                                if let Some(pos) = updated_output_file.rfind('\\') {
                                                    let directory_path = &updated_output_file[..pos];
                                                    ensure_directory_exists(directory_path)
                                                        .expect("Failed to create or access output directory");
                                                }
                                            }
                                            updated_output_file
                                        },
                                        None => "".to_string(),
                                    };
                                    let output_file = updated_output_file.as_str();

                                    match exec_type {
                                        config::TypeExec::External => {
                                            let executor_name =
                                                executor.name.clone().expect(MSG_ERROR_CONFIG);
                                            spinner.set_message(format!(
                                                "Processing: `{}` tool",
                                                executor_name
                                            ));
                                            match get_bin(executor_name) {
                                                Ok(bin) => {
                                                    run (
                                                        executor
                                                            .name
                                                            .clone()
                                                            .expect(MSG_ERROR_CONFIG),
                                                        &args,
                                                        config::ExecType::External,
                                                        Some(&bin),
                                                        Some(&output_path),
                                                        &output_file
                                                    );
                                                }
                                                Err(e) => dprintln!("{}", e),
                                            }
                                        }
                                        config::TypeExec::Internal => {
                                            let tool_name = executor.name.expect(MSG_ERROR_CONFIG);
                                            spinner.set_message(format!(
                                                "Processing: `{}` tool",
                                                tool_name
                                            ));
                                            run_internal(&tool_name, &output_file);
                                        }
                                        config::TypeExec::System => {
                                            let executor_name =
                                                executor.name.expect(MSG_ERROR_CONFIG);
                                            spinner.set_message(format!(
                                                "Processing: `{}` tool",
                                                executor_name
                                            ));
                                            run (
                                                executor_name,
                                                &args,
                                                ExecType::System,
                                                None,
                                                None,
                                                &output_file
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
    let tmp_log_filename = &format!("{}.log", ".aralez");
    let tmp_log_file = File::open(tmp_log_filename).expect("Unable to open the log file");
    drop(tmp_log_file);
    if Path::new(root_output).exists() {
        let destination_file = format!("{}/{}", root_output, logfile);
        fs::rename(tmp_log_filename, &destination_file)?;
    } else {
        println!("[WARN] Root file not found");
    }

    spinner.set_message("Running: compression");

    zip_dir(root_output)?;

    remove_dir_all(root_output)?;

    spinner.finish_with_message("Tasks completed");

    Ok(())
}

fn zip_dir(dir_name: &str) -> io::Result<()> {
    let root_path = Path::new(dir_name);
    fs::create_dir_all(&root_path)?;

    let zip_file_name = format!("{}.zip", dir_name);
    let zip_file = File::create(&zip_file_name)?;

    let mut zip = ZipWriter::new(zip_file);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(true);

    add_directory_to_zip(&mut zip, root_path, "", &options)?;

    zip.finish()?;
    Ok(())
}

fn add_directory_to_zip<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    root_path: &Path,
    parent_dir: &str,
    options: &FileOptions<()>,
) -> io::Result<()> {
    for entry in fs::read_dir(root_path)? {
        let entry = entry?;
        let path = entry.path();
        let name = format!("{}{}", parent_dir, entry.file_name().to_string_lossy());

        if path.exists() {
            if path.is_dir() {
                zip.add_directory(&format!("{}/", name), *options)?;
                add_directory_to_zip(zip, &path, &format!("{}/", name), options)?;
            } else {
                let mut file = File::open(&path)?;
    
                // Retrieve last modified time and convert to DateTime components
                let metadata = file.metadata()?;
                let modified_time = metadata.modified()?.duration_since(UNIX_EPOCH).unwrap_or_default();
                let datetime = DateTime::<Utc>::from(UNIX_EPOCH + modified_time);
                let naive_datetime = datetime.naive_utc();
    
                // Convert to ZipDateTime using date and time components
                let zip_datetime = ZipDateTime::from_date_and_time(
                    naive_datetime.year() as u16,
                    naive_datetime.month() as u8,
                    naive_datetime.day() as u8,
                    naive_datetime.hour() as u8,
                    naive_datetime.minute() as u8,
                    naive_datetime.second() as u8,
                ).unwrap_or_else(|_| ZipDateTime::default_for_write());
    
                // Set options with the zip DateTime
                let file_options = options.clone().last_modified_time(zip_datetime);
    
                zip.start_file(name, file_options)?;
                io::copy(&mut file, zip)?;
            }
        }
    }

    Ok(())
}
