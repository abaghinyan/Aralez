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
mod utils;
mod path;
mod resource_check;

use execute::run;
use path::{insert_if_valid, remove_drive_letter};
use anyhow::Result;
use clap::Parser;
use clap::{Arg, Command};
use config::{get_config, set_config, Config, Entries, ExecType, SearchConfig, SectionConfig};
use indicatif::{ProgressBar, ProgressStyle};
use reader::fs::{process_drive_artifacts, get_default_drive};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::{HashMap, HashSet};
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
use resource_check::check_memory;
use chrono::Local;

#[cfg(target_os = "windows")]
pub mod resource;

#[cfg(target_os = "windows")]
mod explorer {
    pub mod ntfs;
    pub mod fs;
}

#[cfg(target_os = "windows")]
mod reader {
    pub mod ntfs;
    pub mod fs;
    pub mod sector;
}

#[cfg(target_os = "windows")]
pub mod windows_imports {
    pub use crate::execute::{get_list_tools, run_internal, get_bin};
    pub use crate::resource::{add_resource, list_resources, remove_resource};
    pub use crate::reader::ntfs::process_all_drives;
    pub use crate::resource::extract_resource;
}

#[cfg(target_os = "windows")]
use windows_imports::*;

#[cfg(target_os = "linux")]
mod explorer {
    pub mod fs;
    pub mod ntfs;
    pub mod ext4;
}

#[cfg(target_os = "linux")]
mod reader {
    pub mod ext4;
    pub mod fs;
    pub mod ntfs;
    pub mod sector;
}

#[cfg(target_os = "linux")]
pub mod linux_imports {
    pub use std::io::Read;
    pub use super::config::{CONFIG_MARKER_START, CONFIG_MARKER_END};
    pub use std::fs::OpenOptions;
    pub use users::get_effective_uid;
    pub use crate::execute::{run_internal};
}

#[cfg(target_os = "linux")]
use linux_imports::*;

use crate::resource_check::should_continue_collection;

#[derive(Parser)]
struct Cli {
    /// Activate debug mode even in release builds
    #[arg(long)]
    debug: bool,

    /// Show the configuration file and exit
    #[arg(long)]
    show_config: bool,

    /// Specify the default drive to process
    #[arg(long)]
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

#[cfg(target_pointer_width = "64")]
const TARGET_ARCH: &str = "x86_64";

#[cfg(target_pointer_width = "32")]
const TARGET_ARCH: &str = "x86";

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
    let drive_path = if cfg!(target_os = "windows") {
        format!("{}:\\", drive)
    } else {
        drive.to_string()
    };
    fs::metadata(&drive_path).is_ok()
}

fn update_embedded_config(config_path: &str, output_path: &str) -> std::io::Result<()> {
    let current_exe = env::current_exe()?;
    fs::copy(&current_exe, &output_path)?;

    #[cfg(target_os = "linux")]
    {
        let new_config_data = fs::read(config_path)?;
        let mut file = OpenOptions::new().read(true).write(true).open(&output_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        use std::io::SeekFrom;
        let start_pos = buffer
            .windows(CONFIG_MARKER_START.len())
            .rposition(|w| w == CONFIG_MARKER_START);
        let end_pos = buffer
            .windows(CONFIG_MARKER_END.len())
            .rposition(|w| w == CONFIG_MARKER_END)
            .map(|p| p + CONFIG_MARKER_END.len());

        match (start_pos, end_pos) {
            (Some(start), Some(end)) if end > start && end - start > 36 => {
                file.set_len(start as u64)?;
                file.seek(SeekFrom::Start(start as u64))?;
            }
            _ => {
                file.seek(SeekFrom::End(0))?;
            }
        }

        let config_start_offset = file.stream_position()?;
        file.write_all(CONFIG_MARKER_START)?;
        file.write_all(&new_config_data)?;
        file.write_all(CONFIG_MARKER_END)?;
        file.flush()?;
        file.sync_all()?;

        let config_end_offset = config_start_offset
            + CONFIG_MARKER_START.len() as u64
            + new_config_data.len() as u64
            + CONFIG_MARKER_END.len() as u64;

        file.set_len(config_end_offset)?; 
    }

    #[cfg(target_os = "windows")]
    {
        add_resource(config_path, "config.yml", output_path)?;
    }

    println!("[INFO] Embedded configuration updated in `{}`", output_path);
    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    #[cfg(target_os = "linux")]
    if get_effective_uid() != 0 {
        eprintln!("[WARN] Aralez must be run as root/administrator.");
        eprintln!("Try: sudo ./aralez");
        std::process::exit(1);
    }

    let mut cmd = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("debug")
                .short('v')
                .long("verbos")
                .help("Activate verbos mode")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("change_config")
                .short('c')
                .long("change_config")
                .help("Change the embedded configuration file")
                .value_names(&["CONFIG_FILE", "OUTPUT_FILE"])
                .value_hint(clap::ValueHint::FilePath)
                .num_args(2)
                .required(false),
        )
        .arg(
            Arg::new("show_config")
                .short('s')
                .long("show_config")
                .help("Show the configuration file and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("check_config")
                .short('x')
                .long("check_config")
                .help("Check the configuration file")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("encrypt")
                .short('e')
                .long("encrypt")
                .help("Encrypt the archive with a password by using AES256")
                .value_name("PASSWORD")
        )
        .help_template(HELP_TEMPLATE);
    #[cfg(target_os = "windows")]
    {
        cmd = cmd.arg(
            Arg::new("default_drive")
                .short('d')
                .long("default_drive")
                .help("Specify the default drive to process")
                .value_name("DRIVE")
                .default_value("C"),
        )
        .arg(
            Arg::new("add_tool")
                .short('a')
                .long("add_tool")
                .help("Add a new executable tool to the resources")
                .value_names(&["EXECUTABLE_TOOL_PATH", "OUTPUT_FILE"])
                .value_hint(clap::ValueHint::FilePath)
                .num_args(2)
                .required(false),
        )
        .arg(
            Arg::new("remove_tool")
                .short('r')
                .long("remove_tool")
                .help("Remove an executable tool to the resources")
                .value_names(&["EXECUTABLE_TOOL_NAME", "OUTPUT_FILE"])
                .value_hint(clap::ValueHint::Other)
                .num_args(2)
                .required(false),
        )
        .arg(
            Arg::new("list_tools")
                .short('l')
                .long("list_tools")
                .help("List all external tools")
                .action(clap::ArgAction::SetTrue),
        );
    }

    #[cfg(target_os = "linux")]
    {
        cmd = cmd.arg(
            Arg::new("default_drive")
                .short('d')
                .long("default_drive")
                .help("Specify the mounted NTFS device to process (ex: /dev/loopX)")
                .value_name("DRIVE")
                .required(false),
        );
    }

    let matches = cmd.get_matches();

    // Handle changing the embedded configuration
    if let Some(values) = matches.get_many::<String>("change_config") {
        let args: Vec<_> = values.collect();
        let config_path = args[0];
        let output_path = args[1];
        match Config::check_config_file(&config_path) {
            Ok(_) => {
                if !output_path.is_empty() {
                    
                    match update_embedded_config(config_path, output_path) {
                        Ok(_) => println!("[INFO] The config `{}` was successfully added to `{}`.",config_path, output_path),
                        Err(e) => println!("[ERROR] Problem to add the config {} in the resource. Error: {}", config_path, e),
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
    #[cfg(target_os = "windows")]
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
    #[cfg(target_os = "windows")]
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
    #[cfg(target_os = "windows")]
    if matches.get_flag("list_tools") {
        println!("== External tools ==");
        #[cfg(target_os = "windows")] {
            let ext_list = get_list_tools();
            for tool in ext_list {
                println!("(static) {}",tool);
            }
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

    let mut archive_encrypt = config.encrypt.clone();
    if let Some(_) = matches.get_one::<String>("encrypt") {
        archive_encrypt = matches.get_one::<String>("encrypt").cloned();
    }

    set_config(Config {
        output_filename: format!("{}.log", config.get_output_filename()), // Placeholder (overridden)
        tasks: config.tasks.clone(),
        max_size: config.max_size,
        version: config.version.clone(),
        encrypt: archive_encrypt.clone(),
        memory_limit: config.memory_limit,
        disk_limit: config.disk_limit,
        disk_path: config.disk_path.clone(),
        max_disk_usage_pct: config.max_disk_usage_pct,
        min_disk_space: config.min_disk_space
    });

    // Check if the --debug flag was provided
    if matches.get_flag("debug") {
        env::set_var("DEBUG_MODE", "true");
        println!("Debug mode activated!");
    }

    let root_output = &config.get_output_filename();

    // Print the welcome message
    println!(
        "Welcome to {} version {} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        TARGET_ARCH
    );
    println!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!("Developed by: {}", env!("CARGO_PKG_AUTHORS"));
    println!();

    let globalstarttime = Local::now();
    dprintln!("Aralez version: {} ({})", env!("CARGO_PKG_VERSION"), TARGET_ARCH);
    dprintln!("Configuration version: {} ", &config.version.clone().unwrap_or("unknown".to_string()));

    // Machine resources check
    let global_memory_limit = config.get_global_memory_limit();
    if !check_memory(global_memory_limit as u64) {
        eprintln!("[WARN] Not enough available memory (RAM).");
        dprintln!(
            "[WARN] Not enough available memory (RAM). Required at least: {} MB",
            global_memory_limit
        );
        std::process::exit(1);
    }

    if !should_continue_collection(&config, &root_output) {
        eprintln!("[WARN] Disk space too low");

        std::process::exit(1);
    }

    config.save(root_output)?;
    
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["-", "\\", "|", "/"])
            .template("{spinner:.green} {msg}")?,
    );

    spinner.set_message("Starting tasks...");

    let default_drive_value;
    let default_drive: &String = match matches.get_one::<String>("default_drive") {
        Some(val) => val,
        None => {
            default_drive_value = get_default_drive();
            &default_drive_value
        }
    };

    
    let sorted_tasks = config.get_tasks();
    for (section_name, mut section_config) in sorted_tasks {
        if let Some(disabled_task) = section_config.disabled {
            if disabled_task {
                continue;
            }
        }
        dprintln!("[INFO] == Starting task `{}` ==", section_name);
        spinner.set_message(format!("Processing: `{}` task", section_name));

        // Check the disk space before starting the task
        if !should_continue_collection(&config, &root_output) {
            eprintln!("[WARN] Remaining disk space too low. Stopping collection to prevent exceeding disk limits. Collection process terminated before completion.");
            dprintln!("[WARN] Remaining disk space too low. Stopping collection to prevent exceeding disk limits. Collection process terminated before completion.");
            break;
        }

        match section_config.r#type {
            config::TypeTasks::Collect => {
                if let Some(_) = section_config.entries {
                    let drive: String = section_config
                        .drive
                        .clone()
                        .unwrap_or_else(|| default_drive.to_string());
                    spinner.set_message(format!("Processing: `{}` drive", drive));

                    if drive == "*" {
                        #[cfg(target_os = "windows")] {
                            let output_collect_folder = match section_config.get_output_folder(){
                                Some(o) => o.replace("{{root_output_path}}", root_output),
                                None => root_output.to_string(),
                            };
                            process_all_drives(&mut section_config, &output_collect_folder)?;
                        }
                    } else {
                        // Check if the drive exists
                        if !is_drive_accessible(&drive) {
                            dprintln!("[ERROR] Drive `{}` is not accessible or does not exist", drive);
                        } else {
                            let output_collect_folder = match section_config.get_output_folder() {
                                Some(o) => o.replace("{{root_output_path}}", root_output)
                                    .replace("{{drive}}", &drive),
                                #[cfg(target_os = "windows")]
                                None => format!("{}\\{}", root_output, drive),
                                #[cfg(target_os = "linux")]
                                None => format!("{}/{}", root_output, drive),
                            };
                            ensure_directory_exists(&output_collect_folder)?;
                            process_drive_artifacts(&drive, &mut section_config,
                                &output_collect_folder)?;
                        }
                    }
                }
            }
            config::TypeTasks::Execute => {
                if let Some(entries) =  &section_config.entries {
                    entries.par_iter()
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

                                    let executor_name =
                                    executor.name.clone().expect(MSG_ERROR_CONFIG);
                                    spinner.set_message(format!(
                                        "Processing: `{}` tool",
                                        executor_name
                                    ));

                                    // Sanitize output_file
                                    let updated_output_file = match executor.output_file {
                                        Some(output_file) => {
                                            let updated_output_file: String = output_file.to_string();
                                            if let Some(pos) = updated_output_file.rfind('\\') {
                                                let directory_path = &updated_output_file[..pos];
                                                ensure_directory_exists(directory_path)
                                                    .expect("Failed to create or access output directory");
                                            }
                                            updated_output_file
                                        },
                                        None => executor_name.clone().replace(".exe", ".txt").to_string(),
                                    };
                                    let output_file = updated_output_file.as_str();
                                    let output_exec_folder = match section_config.get_output_folder(){
                                        Some(o) => o.replace("{{root_output_path}}", root_output),
                                        None => format!("{}\\{}", root_output, "tools"),
                                    };
                                    ensure_directory_exists(&output_exec_folder)
                                        .expect("Failed to create or access output directory");
                                    let output_fullpath: String = if cfg!(target_os = "windows") {
                                        format!("{}\\{}",output_exec_folder,output_file)
                                    } else {
                                        format!("{}/{}",output_exec_folder,output_file)
                                    };

                                    match exec_type {
                                        #[cfg(target_os = "windows")] 
                                        config::TypeExec::External => {
                                            match get_bin(executor_name) {
                                                Ok(bin) => {
                                                    let result = run (
                                                        executor
                                                            .name
                                                            .clone()
                                                            .expect(MSG_ERROR_CONFIG),
                                                        &args,
                                                        config::ExecType::External,
                                                        Some(&bin),
                                                        Some(&output_path),
                                                        &output_fullpath,
                                                        section_config.memory_limit,
                                                        section_config.timeout
                                                    );
                                                    if let Some(link_element) = executor.link {
                                                        match config.get_task(link_element.clone()) {
                                                            Some(task) => {
                                                                if let Some(res) = result {
                                                                    collect_exec_result(&section_config, res, task.clone(), root_output, &default_drive);
                                                                }
                                                            },
                                                            None => dprintln!("[WARN] Specified link {} for {}, not found", &link_element, executor.name.clone().expect(MSG_ERROR_CONFIG)),
                                                        }
                                                    }
                                                }
                                                Err(e) => dprintln!("{}", e),
                                            }
                                        }
                                        #[cfg(target_os = "windows")] 
                                        config::TypeExec::Internal => {
                                            let result = run_internal(&executor_name, &output_fullpath);
                                            if let Some(link_element) = executor.link {
                                                match config.get_task(link_element.clone()) {
                                                    Some(task) => {
                                                        if let Some(res) = result {
                                                            collect_exec_result(&section_config, res, task.clone(), root_output, &default_drive);
                                                        }
                                                    },
                                                    None => dprintln!("[WARN] Specified link {} for {}, not found", &link_element, executor.name.clone().expect(MSG_ERROR_CONFIG)),
                                                }
                                            }
                                        }
                                        #[cfg(target_os = "linux")] 
                                        config::TypeExec::Internal => {
                                            let result = run_internal(&executor_name, &output_fullpath);
                                            if let Some(link_element) = executor.link {
                                                match config.get_task(link_element.clone()) {
                                                    Some(task) => {
                                                        if let Some(res) = result {
                                                            collect_exec_result(&section_config, res, task.clone(), root_output, &default_drive);
                                                        }
                                                    },
                                                    None => dprintln!("[WARN] Specified link {} for {}, not found", &link_element, executor.name.clone().expect(MSG_ERROR_CONFIG)),
                                                }
                                            }
                                        }
                                        config::TypeExec::System => {
                                            let result = run (
                                                executor_name,
                                                &args,
                                                ExecType::System,
                                                None,
                                                None,
                                                &output_fullpath,
                                                section_config.memory_limit,
                                                section_config.timeout
                                            );
                                            if let Some(link_element) = executor.link {
                                                match config.get_task(link_element.clone()) {
                                                    Some(task) => {
                                                        if let Some(res) = result {
                                                            collect_exec_result(&section_config, res, task.clone(), root_output, &default_drive);
                                                        }
                                                    },
                                                    None => dprintln!("[WARN] Specified link {} for {}, not found", &link_element, executor.name.clone().expect(MSG_ERROR_CONFIG)),
                                                }
                                            }
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
    }

    let globalelapsed = Local::now() - globalstarttime;
    dprintln!("[INFO] All tasks completed in around {:?} sec", globalelapsed.num_seconds());

    let src_log_file = format!("{}.log", root_output);
    // Move the logfile into the root folder
    if Path::new(&src_log_file).exists() {
        let dest_log_file = format!("{}/{}", root_output, src_log_file);
        fs::rename(src_log_file, dest_log_file)?;
    } else {
        println!("[WARN] Log file not found");
    }

    spinner.set_message("Running: compression");

    zip_dir(root_output, archive_encrypt)?;

    remove_dir_all(root_output)?;

    spinner.finish_with_message("Tasks completed");

    Ok(())
}

fn collect_exec_result(section_config: &SectionConfig, result: String, task: SectionConfig, root_output: &str, default_drive: &String) {
    let files_path: Vec<String> = result.lines().map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()) 
        .collect();
    let mut file_entries:HashSet<String> = HashSet::new();
    for file_path in files_path {
        insert_if_valid(&mut file_entries, &file_path);
    }
    let file_entries_vec = file_entries.into_iter().map(|path| remove_drive_letter(&path)).collect();

    let search_config = SearchConfig {
        root_path: Some("\\".to_owned()),
        name: None,
        output_file: None,
        args: None,
        objects: Some(file_entries_vec),
        encrypt: None,
        r#type: None,
        exec_type: None,
        max_size: None,
        link: None,
    };
    let entries_f = HashMap::from([("services".to_string(), vec![search_config])]);
    let mut sc = task;
    sc.entries = Some(Entries(entries_f));

    let drive: String = section_config
    .drive
    .clone()
    .unwrap_or_else(|| default_drive.to_string());

    let output_collect_folder = match sc.get_output_folder() {
        Some(o) => o.replace("{{root_output_path}}", root_output)
                            .replace("{{drive}}", &drive),
        #[cfg(target_os = "windows")]
        None => format!("{}\\{}", root_output, drive),
        #[cfg(target_os = "linux")]
        None => format!("{}/{}", root_output, drive),
    };
    ensure_directory_exists(&output_collect_folder)
        .expect("Failed to create or access output directory");
    let _ = process_drive_artifacts(&drive, &mut sc,
        &output_collect_folder);
}

fn zip_dir(dir_name: &str, encrypt: Option<String>) -> io::Result<()> {
    let root_path = Path::new(dir_name);
    fs::create_dir_all(&root_path)?;

    let zip_file_name = format!("{}.zip", dir_name);
    let zip_file = File::create(&zip_file_name)?;

    let mut zip = ZipWriter::new(zip_file);
    let mut options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(true);

    let password_ref = encrypt.as_ref(); // Get a reference to the original Option<Vec<u8>>

    if let Some(password) = password_ref {
        options = options.with_aes_encryption(zip::AesMode::Aes256, password);
    }

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
