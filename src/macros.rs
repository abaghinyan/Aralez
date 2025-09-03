//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

#[macro_export]
macro_rules! dprintln {
    ($($arg:tt)*) => {
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use chrono::Local;
            use crate::get_config;

            // Retrieve dynamic log filename from the global config
            let tmp_logfile = get_config().get_output_filename();
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&tmp_logfile)
                .expect(&format!("[ERROR] Unable to open or create {}", tmp_logfile).as_str());

            // Get current timestamp
            let now = Local::now();
            let timestamp = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();

            // Write log to file
            writeln!(file, "[{}] {}", timestamp, format!($($arg)*)).expect(&format!("Unable to write to {}", tmp_logfile).as_str());

            // Print to console only if debug mode is enabled
            if cfg!(debug_assertions) || std::env::var("DEBUG_MODE").is_ok() {
                println!("[{}] {}", timestamp, format!($($arg)*));
            }
        }
    };
}
