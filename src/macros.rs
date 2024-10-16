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

            let tmp_logfile =  &format!("{}.log", ".aralez");

            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&tmp_logfile)
                .expect(&format!("[ERROR] Unable to open or create {}",  tmp_logfile).as_str());

            // Get the current local timestamp
            let now = Local::now();
            let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();

            // Write formatted output to the file with the timestamp
            writeln!(file, "[{}] {}", timestamp, format!($($arg)*)).expect(&format!("Unable to write to {}", tmp_logfile).as_str());

            // Print to the console only if debug assertions are active or DEBUG_MODE is set
            if cfg!(debug_assertions) || std::env::var("DEBUG_MODE").is_ok() {
                println!("[{}] {}", timestamp, format!($($arg)*));
            }
        }
    };
}
