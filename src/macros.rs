//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2024 Areg Baghinyan. All Rights Reserved.
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
            use crate::config::GLOBAL_CONFIG;

            let log_file_path =  &format!("{}.log", GLOBAL_CONFIG.get_output_filename());

            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&log_file_path)
                .expect(&format!("[ERROR] Unable to open or create {}",  log_file_path).as_str());

            // Get the current local timestamp
            let now = Local::now();
            let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();

            // Write formatted output to the file with the timestamp
            writeln!(file, "[{}] {}", timestamp, format!($($arg)*)).expect(&format!("Unable to write to {}", log_file_path).as_str());

            // Print to the console only if debug assertions are active or DEBUG_MODE is set
            if cfg!(debug_assertions) || std::env::var("DEBUG_MODE").is_ok() {
                println!("[{}] {}", timestamp, format!($($arg)*));
            }
        }
    };
}
