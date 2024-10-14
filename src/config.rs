//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::utils::{remove_trailing_backslashes, replace_env_vars};
use anyhow::Result;
use chrono::prelude::*;
use hostname::get;
use indexmap::IndexMap;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, env};
use std::fs::{File, create_dir_all};
use std::path::Path;
use std::io::{Read, Write};

pub const CONFIG_MARKER_START: &[u8] = b"# CONFIG_START";
pub const CONFIG_MARKER_END: &[u8] = b"# CONFIG_END";

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub tasks: IndexMap<String, SectionConfig>,
    pub output_filename: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SectionConfig {
    pub priority: u8,
    pub r#type: TypeTasks,
    pub drive: Option<String>,
    pub exclude_drives: Option<Vec<String>>,
    pub entries: IndexMap<String, Vec<SearchConfig>>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum TypeConfig {
    Glob,
}

impl Serialize for TypeConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            TypeConfig::Glob => serializer.serialize_str("glob"),
        }
    }
}

impl<'de> Deserialize<'de> for TypeConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypeConfigVisitor;

        impl<'de> Visitor<'de> for TypeConfigVisitor {
            type Value = TypeConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string containing 'glob'")
            }

            fn visit_str<E>(self, value: &str) -> Result<TypeConfig, E>
            where
                E: de::Error,
            {
                match value {
                    "glob" => Ok(TypeConfig::Glob),
                    _ => Err(de::Error::unknown_variant(
                        value,
                        &["glob"],
                    )),
                }
            }
        }

        deserializer.deserialize_str(TypeConfigVisitor)
    }
}

#[derive(Debug, Clone)]
pub enum TypeTasks {
    Execute,
    Collect,
}

impl Serialize for TypeTasks {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            TypeTasks::Execute => serializer.serialize_str("execute"),
            TypeTasks::Collect => serializer.serialize_str("collect"),
        }
    }
}

impl<'de> Deserialize<'de> for TypeTasks {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypeTasksVisitor;

        impl<'de> Visitor<'de> for TypeTasksVisitor {
            type Value = TypeTasks;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string containing 'execute' or 'collect'")
            }

            fn visit_str<E>(self, value: &str) -> Result<TypeTasks, E>
            where
                E: de::Error,
            {
                match value {
                    "execute" => Ok(TypeTasks::Execute),
                    "collect" => Ok(TypeTasks::Collect),
                    _ => Err(de::Error::unknown_variant(value, &["execute", "collect"])),
                }
            }
        }

        deserializer.deserialize_str(TypeTasksVisitor)
    }
}

#[derive(Debug, Clone)]
pub enum TypeExec {
    External,
    Internal,
    System,
}

impl Serialize for TypeExec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            TypeExec::External => serializer.serialize_str("external"),
            TypeExec::Internal => serializer.serialize_str("internal"),
            TypeExec::System => serializer.serialize_str("system"),
        }
    }
}

impl<'de> Deserialize<'de> for TypeExec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypeExecVisitor;

        impl<'de> Visitor<'de> for TypeExecVisitor {
            type Value = TypeExec;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string containing 'external', 'internal' or 'system")
            }

            fn visit_str<E>(self, value: &str) -> Result<TypeExec, E>
            where
                E: de::Error,
            {
                match value {
                    "external" => Ok(TypeExec::External),
                    "internal" => Ok(TypeExec::Internal),
                    "system" => Ok(TypeExec::System),
                    _ => Err(de::Error::unknown_variant(
                        value,
                        &["external", "internal", "system"],
                    )),
                }
            }
        }

        deserializer.deserialize_str(TypeExecVisitor)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SearchConfig {
    pub dir_path: Option<String>,
    pub name: Option<String>,
    pub output_file: Option<String>,
    pub args: Option<Vec<String>>,
    pub objects: Option<Vec<String>>,
    pub max_size: Option<u64>,
    pub encrypt: Option<String>,
    pub r#type: Option<TypeConfig>,
    pub exec_type: Option<TypeExec>,
}

impl Config {
    pub fn load_from_embedded() -> Result<Self> {
        // Embed the YAML content directly into the binary
        let yaml_data = include_str!("../config/.config.yml");
        let config: Config = serde_yaml::from_str(yaml_data)?;
        Ok(config)
    }

    pub fn load() -> Result<Self> {
        // Load configuration: Try to load the embedded configuration first, then fallback to default
        let config_data = Config::load_embedded_config()?;
        let config: Config = match serde_yaml::from_str(&config_data) {
            Ok(config) => config,
            Err(_e) => Config::load_from_embedded()?,
        };

        Ok(config)
    }

    // Function to load the embedded configuration at runtime
    fn load_embedded_config() -> Result<String> {
        let current_exe = env::current_exe()?;
        let mut file = File::open(current_exe)?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if let Some(start) = Config::find_marker(&buffer, CONFIG_MARKER_START) {
            if let Some(end) = Config::find_marker(&buffer[start..], CONFIG_MARKER_END) {
                let config_data = &buffer[start + CONFIG_MARKER_START.len()..start + end];
                let config_string = String::from_utf8_lossy(config_data);
                return Ok(config_string.into_owned());
            }
        }

        Err(anyhow::anyhow!(
            "Embedded configuration not found or the config file is not valid"
        ))
    }

    // Helper function to find the marker in the binary data
    fn find_marker(data: &[u8], marker: &[u8]) -> Option<usize> {
        data.windows(marker.len())
            .rposition(|window| window == marker) // rposition finds the last occurrence
    }

    pub fn save(&self, output_dir: &str) -> std::io::Result<()> {
        let yaml_string = serde_yaml::to_string(&self).expect("Failed to serialize config to YAML");
    
        // Ensure the root_output folder exists
        let path = Path::new(output_dir);
        if !path.exists() {
            create_dir_all(path)?;
        }
    
        // Define the output file path
        let config_file_path = path.join("config.yml");
    
        // Write the YAML string to the file
        let mut file = File::create(config_file_path)?;
        file.write_all(yaml_string.as_bytes())?;
        Ok(())
    }

    pub fn get_output_filename(&self) -> String {
        let machine_name = get()
            .ok()
            .and_then(|hostname| hostname.into_string().ok())
            .unwrap_or_else(|| "machine".to_string());

        let local: DateTime<Local> = Local::now();
        let datetime = local.format("%Y-%m-%d_%H-%M-%S").to_string();

        let mut vars: IndexMap<&str, &str> = IndexMap::new();
        vars.insert("hostname", &machine_name);
        vars.insert("datetime", &datetime);

        let mut output_filename_expand = self.output_filename.clone();

        for (key, value) in vars {
            output_filename_expand =
                output_filename_expand.replace(&format!("{{{{{}}}}}", key), value);
        }
        output_filename_expand
    }

    /// Function to return tasks sections ordered by priority
    pub fn get_tasks(&self) -> Vec<(String, SectionConfig)> {
        let mut tasks_vec: Vec<(String, SectionConfig)> = self.tasks.clone().into_iter().collect();

        // Sort by priority
        tasks_vec.sort_by_key(|(_, section)| section.priority);

        tasks_vec
    }
}

impl SearchConfig {
    // Method to get dir_path with environment variables replaced
    pub fn get_expanded_dir_path(&self) -> String {
        replace_env_vars(&self.dir_path.clone().unwrap_or_default())
    }

    // Method to sanitize dir_path and objects based on metacharacters
    pub fn sanitize(&mut self) -> Result<(), String> {
        if let Some(dir_path_item) = &self.dir_path {
            let dir_path = remove_trailing_backslashes(&dir_path_item);

            // Check if the dir_path contains a glob element (*, **, ?, or bracketed expressions)
            if dir_path.contains("*")
                || dir_path.contains("?")
                || dir_path.contains("[")
                || dir_path.contains("]")
            {
                let parts: Vec<&str> = dir_path.split("\\").collect();

                // Extract the common part (before any glob or metacharacter)
                let mut new_dir_path = String::new();
                let mut remaining_path = Vec::new();

                for part in parts.iter() {
                    if part.contains("*")
                        || part.contains("**")
                        || part.contains("?")
                        || part.contains("[")
                        || part.contains("]")
                    {
                        remaining_path.push(part.to_string());
                    } else {
                        if !remaining_path.is_empty() {
                            remaining_path.push(part.to_string());
                        } else {
                            if !new_dir_path.is_empty() {
                                new_dir_path.push_str("\\");
                            }
                            new_dir_path.push_str(part);
                        }
                    }
                }

                // If there's no remaining path, assume it's for the current directory
                let remaining_path_str = if !remaining_path.is_empty() {
                    remaining_path.join("\\")
                } else {
                    "*".to_string() // A wildcard to match anything in the current directory
                };

                // Update objects by prepending the remaining path to each object pattern
                if let Some(ref mut objects) = self.objects {
                    for object in objects.iter_mut() {
                        *object = format!("{}\\{}", remaining_path_str, object);
                    }
                }

                // Update the dir_path with the new common part
                self.dir_path = Some(new_dir_path);
            }
        }

        Ok(())
    }
}
