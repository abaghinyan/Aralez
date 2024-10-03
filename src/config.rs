//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::utils::replace_env_vars;
use anyhow::Result;
use std::collections::HashMap;
use hostname::get;
use chrono::prelude::*;
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, Visitor};
use std::fmt;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub entries: IndexMap<String, Vec<SearchConfig>>,
    pub tools: Vec<ToolConfig>,
    pub win_tools: Vec<ToolConfig>,
    pub output_filename: String,
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

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SearchConfig {
    pub dir_path: String,
    pub objects: Option<Vec<String>>,
    pub max_size: Option<u64>,
    pub encrypt: Option<String>,
    pub r#type: Option<TypeConfig>, 
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ToolConfig {
    pub name: String,
    pub args: Vec<String>,
    pub output_file: String,
}

impl Config {
    pub fn get_output_filename(&self) -> String {

        let machine_name = get()
        .ok()
        .and_then(|hostname| hostname.into_string().ok())
        .unwrap_or_else(|| "machine".to_string());

        let local: DateTime<Local> = Local::now();
        let datetime = local.format("%Y-%m-%d_%H-%M-%S").to_string();

        let mut vars: HashMap<&str, &str> = HashMap::new();
        vars.insert("hostname", &machine_name);
        vars.insert("datetime", &datetime);

        let mut output_filename_expand = self.output_filename.clone();

        for (key, value) in vars {
            output_filename_expand = output_filename_expand.replace(&format!("{{{{{}}}}}", key), value);
        }
        output_filename_expand
    }
}


impl SearchConfig {
    // Method to get dir_path with environment variables replaced
    pub fn get_expanded_dir_path(&self) -> String {
        replace_env_vars(&self.dir_path)
    }
}

impl Config {
    pub fn load_from_embedded() -> Result<Self> {
        // Embed the YAML content directly into the binary
        let yaml_data = include_str!("config.yml");
        let config: Config = serde_yaml::from_str(yaml_data)?;
        Ok(config)
    }

    pub fn expand_placeholders(&self, variables: &HashMap<String, String>) -> Self {
        let expand = |text: &str, vars: &HashMap<String, String>| {
            let mut result = text.to_string();
            for (key, value) in vars {
                result = result.replace(&format!("{{{{{}}}}}", key), value);
            }
            result
        };

        let mut expanded_entries = IndexMap::new();
        
        for (key, configs) in &self.entries {
            let mut expanded_configs = Vec::new();
            for config in configs {
                expanded_configs.push(SearchConfig {
                    dir_path: expand(&config.get_expanded_dir_path(), variables),
                    objects: config.objects.clone(),
                    max_size: config.max_size,
                    encrypt: config.encrypt.clone(),
                    r#type: config.r#type.clone(),
                });
            }
            expanded_entries.insert(key.clone(), expanded_configs);
        }

        Config {
            entries: expanded_entries,
            tools: self.tools.clone(), 
            win_tools: self.win_tools.clone(), 
            output_filename: self.get_output_filename()
        }
    }
}
