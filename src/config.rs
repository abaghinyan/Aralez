//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::utils::replace_env_vars;
use anyhow::Result;
use indexmap::IndexMap;
use hostname::get;
use chrono::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, Visitor};
use std::fmt;
use std::fs;
use std::env;
use std::path::Path;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub tasks: IndexMap<String, SectionConfig>,
    pub output_filename: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SectionConfig {
    pub priority: u8,
    pub r#type: TypeTasks,
    pub entries: IndexMap<String, Vec<SearchConfig>>,
}

#[derive(Debug, Clone)]
pub enum TypeConfig {
    String,
    Glob,
    Regex,
}

impl Serialize for TypeConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            TypeConfig::String => serializer.serialize_str("string"),
            TypeConfig::Glob => serializer.serialize_str("glob"),
            TypeConfig::Regex => serializer.serialize_str("regex"),
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
                formatter.write_str("a string containing 'string', 'glob', or 'regex'")
            }

            fn visit_str<E>(self, value: &str) -> Result<TypeConfig, E>
            where
                E: de::Error,
            {
                match value {
                    "string" => Ok(TypeConfig::String),
                    "glob" => Ok(TypeConfig::Glob),
                    "regex" => Ok(TypeConfig::Regex),
                    _ => Err(de::Error::unknown_variant(value, &["string", "glob", "regex"])),
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
                    _ => Err(de::Error::unknown_variant(value, &["external", "internal", "system"])),
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
        let config_filename = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.yml".to_string());
        let config_path = Path::new("config").join(config_filename);
            // Read the YAML file into a string
        let yaml_data = fs::read_to_string(&config_path)
        .expect(&format!("Error reading configuration file at {:?}", config_path));

        // Deserialize the YAML string into the `Config` struct
        let config: Config = serde_yaml::from_str(&yaml_data)?;

        Ok(config)
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
            output_filename_expand = output_filename_expand.replace(&format!("{{{{{}}}}}", key), value);
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

    pub fn tasks_entries_len(&self) -> u64 {
        let mut len: u64 = 0;
        for (_, section_config) in &self.tasks {
            // Iterate over each entry in the IndexMap (artifacts, etc.)
            for (_, entries) in &section_config.entries {
                len += entries.len() as u64;
            }
        }
        len
    }

}

impl SearchConfig {
    // Method to get dir_path with environment variables replaced
    pub fn get_expanded_dir_path(&self) -> String {
        replace_env_vars(&self.dir_path.clone().unwrap_or_default())
    }

    pub fn get_dir_path (&self) -> String {
        match &self.dir_path {
            Some(path) => path.to_string(),
            None => String::new(),
        }
    }
}
