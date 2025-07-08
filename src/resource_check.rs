#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

use std::path::Path;
use std::fs;

use crate::config::Config;

#[cfg(target_os = "linux")]
pub fn get_mem_available_from_proc() -> Option<u64> {
    use std::fs;

    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemAvailable:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return Some(kb / 1024); // Convert to MB
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn check_memory(required_mb: u64) -> bool {
    if let Some(available_mb) = get_mem_available_from_proc() {
        dprintln!("[INFO] Available RAM: {} MB", available_mb);
        dprintln!("[INFO] Required RAM: {} MB", required_mb);

        return available_mb >= required_mb;
    }
    false
}

#[cfg(target_os = "windows")]
pub fn check_memory(required_mb: u64) -> bool {
    use std::mem::MaybeUninit;

    unsafe {
        let mut mem_status = MaybeUninit::<MEMORYSTATUSEX>::zeroed();
        (*mem_status.as_mut_ptr()).dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

        if GlobalMemoryStatusEx(mem_status.as_mut_ptr()) != 0 {
            let status = mem_status.assume_init();
            let available_mb = status.ullAvailPhys / (1024 * 1024);

            dprintln!("[INFO] Available RAM: {} MB", available_mb);
            dprintln!("[INFO] Required RAM:  {} MB", required_mb);

            return available_mb >= required_mb;
        }
    }

    false
}

pub fn get_total_collected_size<P: AsRef<Path>>(path: P) -> u64 {
    fn dir_size(dir: &Path) -> u64 {
        let mut size = 0;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(metadata) = fs::metadata(&path) {
                        size += metadata.len();
                    }
                } else if path.is_dir() {
                    size += dir_size(&path);
                }
            }
        }
        size
    }

    dir_size(path.as_ref())
}

#[cfg(target_os = "linux")]
pub fn get_total_disk_space(path: &str) -> Option<u64> {
    use libc::statvfs;
    use std::ffi::CString;

    let c_path = CString::new(path).ok()?;
    unsafe {
        let mut stat = std::mem::zeroed();
        if statvfs(c_path.as_ptr(), &mut stat) == 0 {
            Some((stat.f_blocks as u64 * stat.f_frsize as u64) / (1024 * 1024)) // Return MB
        } else {
            None
        }
    }
}

#[cfg(target_os = "windows")]
pub fn get_total_disk_space(path: &str) -> Option<u64> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(Some(0)) // null terminator
        .collect();

    let mut free = 0u64;
    let mut total = 0u64;
    let mut avail = 0u64;

    unsafe {
        let success = GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut avail as *mut u64,
            &mut total as *mut u64,
            &mut free as *mut u64,
        );

        if success != 0 {
            Some(total / (1024 * 1024)) // Convert to MB
        } else {
            None
        }
    }
}

pub fn should_continue_collection(config: &Config, collection_path: &str) -> bool {
    let min_disk_space_mb = config.get_global_disk_limit(); // Now the only constraint
    let disk_check_path = config.get_disk_check_path();     // e.g., "/" or "C:\\"

    // Convert collected size to MB only if path exists
    let collected_size_mb = if std::path::Path::new(collection_path).exists() {
        get_total_collected_size(collection_path) / (1024 * 1024)
    } else {
        0
    };

    match get_total_disk_space(&disk_check_path) {
        Some(total_disk_mb) => {
            let free_disk_mb = total_disk_mb.saturating_sub(collected_size_mb);

            if free_disk_mb < min_disk_space_mb {
                eprintln!(
                    "[WARN] Remaining disk space too low: {} MB left (minimum required: {} MB). \
                    Collection process terminated before completion.",
                    free_disk_mb, min_disk_space_mb
                );                
                dprintln!(
                    "[WARN] Remaining disk space too low: {} MB left (minimum required: {} MB)",
                    free_disk_mb, min_disk_space_mb
                );
                return false;
            }

            true
        }
        None => {
            dprintln!(
                "[WARN] Unable to retrieve disk stats for '{}'. Stopping collection as a precaution.",
                disk_check_path
            );
            false
        }
    }
}
