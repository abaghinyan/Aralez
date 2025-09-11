// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use crate::utils::{remove_trailing_slash, replace_env_vars};
use anyhow::Result;
use chrono::prelude::*;
use hostname::get;
use indexmap::IndexMap;
use once_cell::sync::Lazy;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::Mutex;

#[cfg(target_os = "windows")]
pub mod windows_imports {
    pub use crate::resource::extract_resource;
}

#[cfg(target_os = "windows")]
use windows_imports::*;

#[cfg(target_os = "linux")]
pub mod linux_imports {
    pub const CONFIG_MARKER_START: &[u8] = b"===CONFIG_START===\n";
    pub const CONFIG_MARKER_END: &[u8] = b"===CONFIG_END===\n";
}

#[cfg(target_os = "linux")]
pub use linux_imports::*;

static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| {
    Mutex::new(Config {
        output_filename: "default.log".to_string(),
        tasks: IndexMap::new(),
        max_size: None,
        version: None,
        encrypt: None,
        memory_limit: None,
        disk_limit: None,
        disk_path: None,
        max_disk_usage_pct: None,
        min_disk_space: None,
    })
});

pub fn set_config(new_config: Config) {
    let mut config = CONFIG.lock().unwrap();
    *config = new_config;
}

pub fn get_config() -> Config {
    CONFIG.lock().unwrap().clone()
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub tasks: IndexMap<String, SectionConfig>,
    pub output_filename: String,
    pub max_size: Option<u64>,
    pub version: Option<String>,
    pub encrypt: Option<String>,
    pub memory_limit: Option<usize>, // in MB
    pub disk_limit: Option<u64>,     // in MB
    pub disk_path: Option<String>,
    pub min_disk_space: Option<u64>, // in MB
    pub max_disk_usage_pct: Option<u8>, // e.g. 50 means 50%
}

#[derive(Debug, Clone, Serialize)]
pub struct Entries(pub HashMap<String, Vec<SearchConfig>>);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SectionConfig {
    pub priority: Option<u8>,
    pub r#type: TypeTasks,
    pub drive: Option<String>,
    pub output_folder: Option<String>,
    pub max_size: Option<u64>,
    pub exclude_drives: Option<Vec<String>>,
    pub entries: Option<Entries>,
    pub disabled: Option<bool>,
    pub memory_limit: Option<usize>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeConfig {
    Glob,
}

#[derive(PartialEq)]
pub enum ExecType {
    External,
    System,
}

impl SectionConfig {
    pub fn get_output_folder(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            self.output_folder
                .as_ref()
                .map(|folder| folder.replace('\\', "/"))
        }
        #[cfg(target_os = "windows")]
        {
            self.output_folder.clone()
        }
    }

    /// Returns the min between section max_size and global max_size
    pub fn get_max_size(&self) -> Option<u64> {
        let config = CONFIG.lock().unwrap();
        let config_max_size = config.max_size;
        match (self.max_size, config_max_size) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }
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
                    if !entry_names.insert(key.clone()) {
                        return Err(de::Error::custom(format!(
                            "[ERROR] Config: Duplicate entry name '{}' found",
                            key
                        )));
                    }

                    for config in &configs {
                        // 1. Validate `root_path` if present
                        if let Some(root_path) = &config.root_path {
                            if !root_path.starts_with('\\')
                                && !root_path.starts_with('%')
                                && !root_path.starts_with('/')
                            {
                                return Err(de::Error::custom(format!(
                                    "[ERROR] Config: root_path '{}' in entry '{}' should start with '\\\\', '/', or '%'",
                                    root_path, key
                                )));
                            }
                        }

                        // 2. If entry type is "glob", ensure root_path and objects are present
                        if let Some(type_config) = &config.r#type {
                            if *type_config == TypeConfig::Glob {
                                if config.root_path.is_none() || config.objects.is_none() {
                                    return Err(de::Error::custom(format!(
                                        "[ERROR] Config: Entry '{}' with type 'glob' must have `root_path` and `objects`",
                                        key
                                    )));
                                }
                            }
                        }

                        // 3. max_size must be > 0 if present
                        if let Some(max_size) = config.max_size {
                            if max_size == 0 {
                                return Err(de::Error::custom(
                                    "[ERROR] Config: `max_size` should be greater than zero",
                                ));
                            }
                        }

                        // 4. encrypt shouldn't be empty string
                        if let Some(password) = &config.encrypt {
                            if password.is_empty() {
                                return Err(de::Error::custom(
                                    "[ERROR] Config: `encrypt` should not be empty",
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

#[derive(Debug, Clone, PartialEq)]
pub enum TypeExec {
    System,
    Internal,
    #[cfg(target_os = "windows")]
    External,
}

impl Serialize for TypeExec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            #[cfg(target_os = "windows")]
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

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string containing 'external', 'internal' or 'system'")
            }

            fn visit_str<E>(self, value: &str) -> Result<TypeExec, E>
            where
                E: de::Error,
            {
                match value {
                    "internal" => Ok(TypeExec::Internal),
                    "system" => Ok(TypeExec::System),
                    "external" => {
                        #[cfg(target_os = "linux")]
                        return Err(de::Error::custom(
                            "`exec_type: external` is not available on Linux. Use `internal` or `system`.",
                        ));
                        #[cfg(target_os = "windows")]
                        {
                            Ok(TypeExec::External)
                        }
                    }
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

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct SearchConfig {
    pub root_path: Option<String>,
    pub name: Option<String>,
    pub output_file: Option<String>,
    pub args: Option<Vec<String>>,
    pub objects: Option<Vec<String>>,
    pub encrypt: Option<String>,
    pub r#type: Option<TypeConfig>,
    pub exec_type: Option<TypeExec>,
    pub max_size: Option<u64>,
    pub link: Option<String>,
}

impl Config {
    fn normalize_newlines(mut s: String) -> String {
        if s.contains("\r\n") {
            s = s.replace("\r\n", "\n");
        }
        s
    }

    fn decode_text(bytes: &[u8]) -> Result<String> {
        // UTF-16LE BOM
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let u16s: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16(&u16s)?;
            return Ok(Self::normalize_newlines(s));
        }

        // UTF-16BE BOM
        if bytes.starts_with(&[0xFE, 0xFF]) {
            let u16s: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16(&u16s)?;
            return Ok(Self::normalize_newlines(s));
        }

        // Heuristic: BOM-less UTF-16LE (NUL in every odd byte)
        let looks_like_utf16le =
            bytes.len() > 1 && bytes.iter().skip(1).step_by(2).all(|&b| b == 0);

        if looks_like_utf16le {
            let u16s: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16(&u16s)?;
            return Ok(Self::normalize_newlines(s));
        }

        // Assume UTF-8
        let s = String::from_utf8(bytes.to_vec())?;
        Ok(Self::normalize_newlines(s))
    }

    #[cfg(target_os = "linux")]
    pub fn load_embedded_config() -> Result<String> {
        use std::{env, fs};

        let exe_path = env::current_exe()?;
        let content = fs::read(&exe_path)?;

        let start = content
            .windows(CONFIG_MARKER_START.len())
            .rposition(|w| w == CONFIG_MARKER_START)
            .ok_or_else(|| anyhow::anyhow!("CONFIG_MARKER_START not found"))?;

        let end = content
            .windows(CONFIG_MARKER_END.len())
            .rposition(|w| w == CONFIG_MARKER_END)
            .ok_or_else(|| anyhow::anyhow!("CONFIG_MARKER_END not found"))?;

        if end < start {
            anyhow::bail!("CONFIG_MARKER_END found before CONFIG_MARKER_START");
        }

        let config_bytes = &content[(start + CONFIG_MARKER_START.len())..end];
        let cfg = Self::decode_text(config_bytes)?;
        Ok(cfg)
    }

    #[cfg(target_os = "windows")]
    pub fn load_embedded_config() -> Result<String> {
        let data = extract_resource("config.yml")?; // from crate::resource
        let cfg = Self::decode_text(&data)?;
        Ok(cfg)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    pub fn load_embedded_config() -> Result<String> {
        anyhow::bail!("Embedded config not supported on this platform")
    }

    pub fn load() -> Result<Self, anyhow::Error> {
        let embedded = Self::load_embedded_config();
        if let Ok(data) = embedded {
            if !data.is_empty() {
                return serde_yaml::from_str(&data).map_err(|e| anyhow::anyhow!(e.to_string()));
            }
        }
        Self::load_default()
    }

    pub fn check_config_file(filepath: &String) -> Result<Config, anyhow::Error> {
        let mut file = File::open(filepath)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        let config_string = Self::decode_text(&buffer)?;
        serde_yaml::from_str(&config_string).map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    pub fn load_default() -> Result<Self, anyhow::Error> {
        // NOTE: include_str! requires UTF-8 at compile time.
        let yaml_data = include_str!("../config/.config.yml");
        serde_yaml::from_str(yaml_data).map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    pub fn get_raw_data() -> Result<String> {
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        if let Ok(embedded_config) = Self::load_embedded_config() {
            if !embedded_config.is_empty() {
                return Ok(embedded_config);
            }
        }

        // Fallback to bundled file (decode defensively in case it's not UTF-8)
        let raw: &[u8] = include_bytes!("../config/.config.yml");
        let decoded = Self::decode_text(raw)?;
        Ok(decoded)
    }

    pub fn save(&self, output_dir: &str) -> Result<()> {
        let data = Self::get_raw_data()?;
        let path = Path::new(output_dir);
        if !path.exists() {
            create_dir_all(path)?;
        }
        let config_file_path = path.join("config.yml");
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

    pub fn get_tasks(&self) -> Vec<(String, SectionConfig)> {
        let mut tasks_vec: Vec<(String, SectionConfig)> = self.tasks.clone().into_iter().collect();
        tasks_vec.sort_by_key(|(_, section)| section.priority.unwrap_or(255));
        tasks_vec
    }

    pub fn get_task(&self, name: String) -> Option<&SectionConfig> {
        self.tasks.get(&name)
    }

    pub fn get_global_memory_limit(&self) -> usize {
        // Default: 1 GB if not set (value in MB)
        self.memory_limit.unwrap_or(1 * 1024)
    }

    pub fn get_global_disk_limit(&self) -> u64 {
        // Default to 8 GB (value in MB)
        self.disk_limit.unwrap_or(8 * 1024)
    }

    pub fn get_disk_check_path(&self) -> String {
        if let Some(ref path) = self.disk_path {
            path.clone()
        } else {
            #[cfg(target_os = "windows")]
            {
                "C:\\".to_string()
            }
            #[cfg(target_os = "linux")]
            {
                "/".to_string()
            }
        }
    }
}

impl SearchConfig {
    /// Return the min between the entry max size, the section max size, and the global max size
    pub fn get_max_size(&self, section_config_max_size: Option<u64>) -> Option<u64> {
        let config = CONFIG.lock().unwrap();
        let config_max_size = config.max_size;
        match (self.max_size, section_config_max_size, config_max_size) {
            (Some(search_max), Some(section_max), Some(config_max)) => {
                Some(search_max.min(section_max).min(config_max))
            }
            (Some(search_max), Some(section_max), None) => Some(search_max.min(section_max)),
            (Some(search_max), None, Some(config_max)) => Some(search_max.min(config_max)),
            (None, Some(section_max), Some(config_max)) => Some(section_max.min(config_max)),
            (Some(search_max), None, None) => Some(search_max),
            (None, Some(section_max), None) => Some(section_max),
            (None, None, Some(config_max)) => Some(config_max),
            (None, None, None) => None,
        }
    }

    /// Expand environment variables in root_path
    pub fn get_expanded_root_path(&self) -> String {
        replace_env_vars(&self.root_path.clone().unwrap_or_default())
    }

    /// Sanitize root_path and objects based on glob metacharacters
    pub fn sanitize(&mut self) -> Result<(), String> {
        let root_path_item = &self.get_expanded_root_path();
        let mut root_path = root_path_item.replace('\\', "/");
        root_path = remove_trailing_slash(root_path);

        // Check for glob elements (*, **, ?, [ ])
        if root_path.contains('*')
            || root_path.contains('?')
            || root_path.contains('[')
            || root_path.contains(']')
        {
            let parts: Vec<&str> = root_path.split('/').collect();

            // Extract common part (before any glob)
            let mut new_root_path = String::new();
            let mut remaining_path = Vec::new();

            for part in parts.iter() {
                if part.contains('*')
                    || part.contains("**")
                    || part.contains('?')
                    || part.contains('[')
                    || part.contains(']')
                {
                    remaining_path.push(part.to_string());
                } else {
                    if !remaining_path.is_empty() {
                        remaining_path.push(part.to_string());
                    } else {
                        if !new_root_path.is_empty() {
                            new_root_path.push('/');
                        }
                        new_root_path.push_str(part);
                    }
                }
            }

            // If there's no remaining path, assume current directory
            let remaining_path_str = if !remaining_path.is_empty() {
                remaining_path.join("/")
            } else {
                "*".to_string()
            };

            // Prepend remaining path to each object pattern
            if let Some(ref mut objects) = self.objects {
                for object in objects.iter_mut() {
                    *object = format!("{}/{}", remaining_path_str, object);
                }
            }

            // Update root_path with the new common part
            self.root_path = Some(new_root_path);
        } else {
            self.root_path = Some(root_path);
        }

        Ok(())
    }
}

#[allow(dead_code)]
impl ExecType {
    pub const EXTERNAL: ExecType = ExecType::External;
    pub const SYSTEM: ExecType = ExecType::System;
}
