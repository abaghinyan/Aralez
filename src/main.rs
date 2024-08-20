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
mod ntfs_reader;
mod utils;
mod sector_reader;
mod config; 
mod network_info;
mod process;
mod tool_runner;
mod embin;

use utils::{ensure_directory_exists};
use embin::execute;
use std::path::Path;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{Read, Seek};
use anyhow::Result;
use std::io::BufReader;
use sector_reader::SectorReader;
use crate::command_info::CommandInfo;
use crate::tool_runner::run_tool;
use std::collections::{HashMap, HashSet};
use std::env;
use config::{Config, SearchConfig};  
use hostname::get;
use clap::Parser;
use clap::{Arg, Command};
use zip::{write::FileOptions, ZipWriter};
use std::fs::{self, File};
use std::io::{self, Write};

/// Your application description here.
#[derive(Parser)]
struct Cli {
    /// Activate debug mode even in release builds
    #[arg(long)]
    debuge: bool,
}
const HELP_TEMPLATE: &str = "{bin} {version}
{author}

{about}

USAGE:
    {usage}

{all-args}
";

// Define a struct to hold information about each tool
struct Tool {
    name: &'static str,
    args: &'static [&'static str],
    output_file: &'static str,
}

fn main() -> Result<()> {
    // Print the welcome message
    println!("Welcome to {} version {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!("Developed by: {}", env!("CARGO_PKG_AUTHORS"));
    println!();

    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
    .arg(
        Arg::new("debuge")
            .long("debuge")
            .help("Activate debug mode")
            .action(clap::ArgAction::SetTrue),
    )
    .help_template(HELP_TEMPLATE)
    .get_matches();

    // Check if the --debuge flag was provided
    if matches.get_flag("debuge") {
        env::set_var("DEBUG_MODE", "true");
        println!("Debug mode activated!");
    }
    let machine_name = get()
    .ok()
    .and_then(|hostname| hostname.into_string().ok())
    .unwrap_or_else(|| "machine".to_string());

    let root_output = &machine_name;

    // Load configuration from the embedded YAML content
    let config = Config::load_from_embedded()?;

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

    let output_path = format!("{}\\{}",root_output, "tools"); // Adjust the path as necessary
    ensure_directory_exists(&output_path).expect("Failed to create or access output directory");

    // List of tools with their respective arguments and output files
    let tools = vec![
        Tool { name: "autorunsc.exe", args: &["/accepteula", "/nobanner", "/quiet", "/all"], output_file: "autorunsc.txt" },
        Tool { name: "handle.exe", args: &["/accepteula", "/a", "/nobanner"], output_file: "handle.txt" },
        Tool { name: "tcpvcon.exe", args: &["-a"], output_file: "tcpvcon.txt" }, 
        Tool { name: "pslist.exe", args: &["/accepteula", "/all"], output_file: "pslist.txt" },
        Tool { name: "Listdlls.exe", args: &["/accepteula"], output_file: "listdlls.txt" }, 
        Tool { name: "PsService.exe", args: &["/accepteula", "query"], output_file: "psservice.txt" },
    ];
    // Iterate through each tool, execute it, and save the output
    for tool in tools {
        let exe_bytes: &[u8] = match tool.name {
            "autorunsc.exe" => include_bytes!("../tools/autorunsc.exe"),
            "handle.exe" => include_bytes!("../tools/handle.exe"),
            "tcpvcon.exe" => include_bytes!("../tools/tcpvcon.exe"),
            "pslist.exe" => include_bytes!("../tools/pslist.exe"),
            "Listdlls.exe" => include_bytes!("../tools/Listdlls.exe"),
            "PsService.exe" => include_bytes!("../tools/PsService.exe"),
            _ => return Err(anyhow::anyhow!("Tool not found")),
        };

        execute(exe_bytes, tool.name, &output_path, tool.args)?;
    }

    // WinTools
    let win_tools = vec![
        Tool { name: "netstat.exe", args: &["-anob"], output_file: "netstat.txt" },
        Tool { name: "ipconfig.exe", args: &["/all"], output_file: "ipconfig.txt" },
        Tool { name: "ipconfig.exe", args: &["/displaydns"], output_file: "dnscache.txt" },
        Tool { name: "systeminfo.exe", args: &[], output_file: "systeminfo.txt" },
        Tool { name: "tasklist.exe", args: &["/v", "/fo", "csv"], output_file: "tasklist.csv" },
        Tool { name: "net.exe", args: &["share"], output_file: "netshare.csv" },
    ];

    for tool in win_tools {
        match run_tool(tool.name, tool.args, tool.output_file, &output_path) {
            Ok(_) => {
                pb.inc(1); // Increment the progress bar
                pb.set_message(format!("Processing: {} tool", tool.name));
            }
            Err(e) => dprintln!("Error running {}: {}", tool.name, e),
        }
    }

    // Processes info
    let path = Path::new(&output_path);
    let filename = "ps_info.txt";
    if let Err(e) = process::run_ps(filename, path) {
        dprintln!("Error: {}", e);
    } else {
        pb.inc(1); // Increment the progress bar
        pb.set_message(format!("Processing: {} tool", "ps_info"));
    }

    // Network info 
    let filename = "ports_info.txt";
    let path = Path::new(&output_path);

    if let Err(e) = network_info::run_network_info(filename, path) {
        dprintln!("Error writing network info: {}", e);
    } else {
        pb.inc(1); // Increment the progress bar
        pb.set_message(format!("Processing: {} tool", "network_info"));
    }


    // Get Files

    // Track already processed paths
    let mut processed_paths = HashSet::new();

    // Process each consolidated configuration
    for (user, search_config) in consolidated_configs {
        let path_key = format!("{}\\{:?}", search_config.dir_path, search_config.extensions.clone().unwrap_or_default());

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

fn search_in_config<T>(info: &mut CommandInfo<T>, config: &SearchConfig, root_output: &str) -> Result<()> 
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