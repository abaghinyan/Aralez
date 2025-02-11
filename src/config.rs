//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::resource::extract_resource;
use crate::utils::{remove_trailing_slash, replace_env_vars};
use anyhow::Result;
use chrono::prelude::*;
use hostname::get;
use indexmap::IndexMap;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::fmt;
use once_cell::sync::Lazy;
use std::sync::Mutex;

// Global static config
static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config {
    output_filename: "default.log".to_string(), // Placeholder
    tasks: IndexMap::new(),
}));

/// **Function to update the global config instance**
pub fn set_config(new_config: Config) {
    let mut config = CONFIG.lock().unwrap();
    *config = new_config;
}

/// **Function to retrieve the current config**
pub fn get_config() -> Config {
    CONFIG.lock().unwrap().clone()
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub tasks: IndexMap<String, SectionConfig>,
    pub output_filename: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entries(HashMap<String, Vec<SearchConfig>>);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SectionConfig {
    pub priority: u8,
    pub r#type: TypeTasks,
    pub drive: Option<String>,
    pub output_folder: Option<String>,
    pub max_size: Option<u64>,
    pub exclude_drives: Option<Vec<String>>,
    pub entries: Entries,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeConfig {
    Glob,
}

#[derive(PartialEq)]
pub enum ExecType {
    External,
    System
}

// Implement IntoIterator for `&Entries`
impl<'a> IntoIterator for &'a Entries {
    type Item = (&'a String, &'a Vec<SearchConfig>);
    type IntoIter = std::collections::hash_map::Iter<'a, String, Vec<SearchConfig>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

// Implement IntoIterator for consuming `Entries`
impl IntoIterator for Entries {
    type Item = (String, Vec<SearchConfig>);
    type IntoIter = std::collections::hash_map::IntoIter<String, Vec<SearchConfig>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Deref for Entries {
    type Target = HashMap<String, Vec<SearchConfig>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Entries {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = Entries;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map of entries with validation checks")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();
                let mut entry_names = HashSet::new(); // Track duplicate keys

                while let Some((key, configs)) = access.next_entry::<String, Vec<SearchConfig>>()? {
                    // Check for duplicate keys
                    if !entry_names.insert(key.clone()) {
                        return Err(de::Error::custom(format!(
                            "[ERROR] Config: Duplicate entry name '{}' found",
                            key
                        )));
                    }

                    // Iterate over each config in the entry to validate fields
                    for config in &configs {
                        // 1. Validate `root_path` if it's present
                        if let Some(root_path) = &config.root_path {
                            if !root_path.starts_with("\\") && !root_path.starts_with('%') {
                                return Err(de::Error::custom(format!(
                                    "[ERROR] Config: root_path '{}' in entry '{}' should start with '\\\\' or '%'", 
                                    root_path, key
                                )));
                            }
                        }

                        // 2. If entry type is "collect", ensure `root_path` and `objects` are present
                        if let Some(type_config) = &config.r#type {
                            if *type_config == TypeConfig::Glob {
                                if config.root_path.is_none() || config.objects.is_none() {
                                    return Err(de::Error::custom(format!(
                                        "[ERROR] Config: Entry '{}' with type 'collect' must have `root_path` and `objects`", 
                                        key
                                    )));
                                }
                            }
                        }

                        // Additional validations for other fields, e.g., `max_size`, `encrypt`
                        if let Some(max_size) = config.max_size {
                            if max_size <= 0 {
                                return Err(de::Error::custom(
                                    "[ERROR] Config: `max_size` should be greater than zero",
                                ));
                            }
                        }

                        // encryp shouldn't be empty
                        if let Some(password) = &config.encrypt {
                            if password.is_empty() || *password == "".to_string() {
                                return Err(de::Error::custom(
                                    "[ERROR] Config: `encrypt` should be empty",
                                ));
                            }
                        }
                    }

                    map.insert(key, configs);
                }

                Ok(Entries(map))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
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
                    _ => Err(de::Error::unknown_variant(value, &["glob"])),
                }
            }
        }

        deserializer.deserialize_str(TypeConfigVisitor)
    }
}

#[derive(Debug, Clone, PartialEq)]
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
    pub root_path: Option<String>,
    pub name: Option<String>,
    pub output_file: Option<String>,
    pub args: Option<Vec<String>>,
    pub objects: Option<Vec<String>>,
    pub encrypt: Option<String>,
    pub r#type: Option<TypeConfig>,
    pub exec_type: Option<TypeExec>,
    max_size: Option<u64>,
}

impl Config {
    pub fn load_default() -> Result<Self, anyhow::Error> {
        // Embed the YAML content directly into the binary
        let yaml_data = include_str!("../config/.config.yml");
        let config: Config = serde_yaml::from_str(yaml_data)?;

        Ok(config)
    }

    pub fn load() -> Result<Self, anyhow::Error> {
        // Load configuration: Try to load the embedded configuration first, then fallback to default
        let config_data = Config::load_embedded_config().unwrap_or(String::new());
        if config_data.is_empty() {
            return match Config::load_default() {
                Ok(conf) => Ok(conf),
                Err(e) => Err(e),
            }
        }
        return match serde_yaml::from_str(&config_data) {
            Ok(config) => Ok(config),
            Err(e) => Err(anyhow::anyhow!(e.to_string()) ),
        };
    }

    pub fn check_config_file(filepath: &String) -> Result<Self, anyhow::Error> {
        let mut file = File::open(filepath)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        let config_string = String::from_utf8_lossy(&buffer);

        return match serde_yaml::from_str(&config_string) {
            Ok(config) => Ok(config),
            Err(e) => Err(anyhow::anyhow!(e.to_string()) ),
        };
    }
    
    // Function to load the embedded configuration at runtime
    pub fn load_embedded_config() -> Result<String, anyhow::Error> {
        let config_data = extract_resource("config.yml")?;
        let config_string = String::from_utf8(config_data)?;

        return Ok(config_string);
    }

    /// Load the raw configuration as a plain string, choosing between embedded or default.
    pub fn get_raw_data() -> Result<String> {
        // Attempt to load the embedded configuration
        if let Ok(embedded_config) = Config::load_embedded_config() {
            if !embedded_config.is_empty() {
                return Ok(embedded_config);
            }
        }
        // If embedded config is not found, fall back to loading the default config file
        let yaml_data = include_str!("../config/.config.yml");

        Ok(yaml_data.to_string())
    }

    pub fn save(&self, output_dir: &str) -> Result<()> {
        let data = Config::get_raw_data()?;

        // Ensure the root_output folder exists
        let path = Path::new(output_dir);
        if !path.exists() {
            create_dir_all(path)?;
        }

        // Define the output file path
        let config_file_path = path.join("config.yml");

        // Write the YAML string to the file
        let mut file = File::create(config_file_path)?;
        file.write_all(data.as_bytes())?;
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
    // Function that return the min between the max size of the task and the entry
    // This part should be improved 
    pub fn get_max_size(&self, section_config_max_size: Option<u64>) -> Option<u64> {
        match (self.max_size, section_config_max_size) {
            (Some(search_max), Some(section_max)) => Some(search_max.min(section_max)), // Return the smaller max_size
            (Some(search_max), None) => Some(search_max), // If section has no max_size, use search_max
            (None, Some(section_max)) => Some(section_max), // If search has no max_size, use section_max
            (None, None) => None, // No max_size defined
        }
    }

    // Method to get root_path with environment variables replaced
    pub fn get_expanded_root_path(&self) -> String {
        replace_env_vars(&self.root_path.clone().unwrap_or_default())
    }

    // Method to sanitize root_path and objects based on metacharacters
    pub fn sanitize(&mut self) -> Result<(), String> {
        let root_path_item = &self.get_expanded_root_path();
        let mut root_path = root_path_item.replace("\\", "/");
        root_path = remove_trailing_slash(root_path);
        // Check if the root_path contains a glob element (*, **, ?, or bracketed expressions)
        if root_path.contains("*")
            || root_path.contains("?")
            || root_path.contains("[")
            || root_path.contains("]")
        {
            let parts: Vec<&str> = root_path.split("/").collect();

            // Extract the common part (before any glob or metacharacter)
            let mut new_root_path = String::new();
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
                        if !new_root_path.is_empty() {
                            new_root_path.push_str("/");
                        }
                        new_root_path.push_str(part);
                    }
                }
            }

            // If there's no remaining path, assume it's for the current directory
            let remaining_path_str = if !remaining_path.is_empty() {
                remaining_path.join("/")
            } else {
                "*".to_string() // A wildcard to match anything in the current directory
            };

            // Update objects by prepending the remaining path to each object pattern
            if let Some(ref mut objects) = self.objects {
                for object in objects.iter_mut() {
                    *object = format!("{}/{}", remaining_path_str, object);
                }
            }

            // Update the root_path with the new common part
            self.root_path = Some(new_root_path);
        } else {
            self.root_path = Some(root_path);
        }

        Ok(())
    }
}
