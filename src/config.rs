//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use serde::Serialize;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub entries: HashMap<String, Vec<SearchConfig>>,
    pub tools: Vec<ToolConfig>,
    pub win_tools: Vec<ToolConfig>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SearchConfig {
    pub dir_path: String,
    pub extensions: Option<Vec<String>>,
    pub max_size: Option<u64>,
    pub encrypt: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ToolConfig {
    pub name: String,
    pub args: Vec<String>,
    pub output_file: String,
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

        let mut expanded_entries = HashMap::new();

        for (key, configs) in &self.entries {
            let mut expanded_configs = Vec::new();
            for config in configs {
                expanded_configs.push(SearchConfig {
                    dir_path: expand(&config.dir_path, variables),
                    extensions: config.extensions.clone(),
                    max_size: config.max_size,
                    encrypt: config.encrypt.clone(),
                });
            }
            expanded_entries.insert(key.clone(), expanded_configs);
        }

        Config {
            entries: expanded_entries,
            tools: self.tools.clone(), // Tools don't need placeholder expansion in this case
            win_tools: self.win_tools.clone(), // WinTools don't need placeholder expansion in this case
        }
    }
}
