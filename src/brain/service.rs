//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use evtx::err::EvtxError;
use evtx::EvtxParser;
use serde_json::Value;
use std::fs::File;
use std::path::Path;
use std::collections::HashSet;

use crate::config::SearchConfig;

use super::path::{insert_if_valid, remove_drive_letter};

/// Loads the EVTX file and returns an `EvtxParser` instance.
///
/// # Arguments
/// * `file_path` - Path to the EVTX file.
///
/// # Returns
/// An `EvtxParser` object ready to parse the file.
pub fn load_evtx(file_path: &str) -> Result<EvtxParser<File>, EvtxError> {
    let path = Path::new(file_path);
    EvtxParser::from_path(path)
}

/// Parses an EVTX file and extracts relevant service-related events.
///
/// # Arguments
/// * `parser` - An `EvtxParser` instance.
///
/// # Returns
/// A vector of JSON objects representing extracted event data.
pub fn parse_evtx(parser: &mut EvtxParser<File>) -> Vec<Value> {
    let mut service_events = Vec::new();

    for record in parser.records_json() {
        if let Ok(event) = record {
            let json: Value = serde_json::from_str(&event.data).unwrap();
            if let Some(event_id) = json["Event"]["System"]["EventID"].as_u64() {
                match event_id {
                    4697 | 7045 | 7036 | 7034 | 4688 | 106 | 200 => { // Relevant service events

                        service_events.push(json.clone());
                    }
                    _ => {}
                }
            }
            if let Some(event_id) = json["Event"]["System"]["EventID"]["#text"].as_u64() {
                match event_id {
                    4697 | 7045 | 7036 | 7034 | 4688 | 106 | 200 => { // Relevant service events
                        service_events.push(json);
                    }
                    _ => {}
                }
            }
        }
    }
    service_events
}

/// Extracts only valid malware file paths from parsed events.
/// Removes arguments and ensures only actual filenames are collected.
pub fn get_services_path(events: Vec<Value>) -> SearchConfig {
    let mut malware_paths: HashSet<String> = HashSet::new();

    for event in events {
        if let Some(path) = event["Event"]["EventData"]["NewProcessName"].as_str() {
            insert_if_valid(&mut malware_paths, path);
        }
        if let Some(path) = event["Event"]["EventData"]["BinaryPathName"].as_str() {
            insert_if_valid(&mut malware_paths, path);
        }
        if let Some(path) = event["Event"]["EventData"]["TargetFilename"].as_str() {
            insert_if_valid(&mut malware_paths, path);
        }
        if let Some(path) = event["Event"]["EventData"]["ImageLoaded"].as_str() {
            insert_if_valid(&mut malware_paths, path);
        }
        if let Some(path) = event["Event"]["EventData"]["ObjectName"].as_str() {
            insert_if_valid(&mut malware_paths, path);
        }
        if let Some(path) = event["Event"]["EventData"]["ImagePath"].as_str() {
            insert_if_valid(&mut malware_paths, path);
        }
    }

    let malware_path_vec = malware_paths.into_iter().map(|path| remove_drive_letter(&path)).collect();

    SearchConfig {
        root_path: Some("\\".to_owned()),
        name: None,
        output_file: None,
        args: None,
        objects: Some(malware_path_vec),
        encrypt: None,
        r#type: None,
        exec_type: None,
        max_size: Some(10000000),
    }
}

