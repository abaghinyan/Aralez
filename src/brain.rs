//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

mod service;
mod path;
mod registry;

use anyhow::Result;
use registry::get_registries_path;
use service::{get_services_path, load_evtx, parse_evtx};

use crate::config::SearchConfig;

pub fn collect_services (drive: &str) -> Result<SearchConfig, anyhow::Error> {
    let evtx_file = format!("{}:\\Windows\\System32\\winevt\\Logs\\System.evtx", drive); // Change to your EVTX file path

    // Load the EVTX parser
    match load_evtx(&evtx_file) {
        Ok(mut parser) => {
            // Parse EVTX to extract service-related logs
            let events = parse_evtx(&mut parser);

            // Extract service binary paths
            let service_paths = get_services_path(events);

            return Ok(service_paths)
        },
        Err(e) => dprintln!("[ERROR] {:?}", e)
    }

    Err(anyhow::anyhow!(format!("[ERROR] System.evtx not found")))
}

pub fn collect_registries () -> SearchConfig {
    let registries = get_registries_path();

    registries
}