use std::fs::File;
use std::io::{Write};
use std::path::Path;
use std::ptr::null_mut;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{CreateFileA, OPEN_EXISTING};
use windows::Win32::Foundation::{GENERIC_READ, CloseHandle};
use windows::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::core::PCWSTR;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::ffi::OsStrExt;
use windows_core::PCSTR;

fn to_pwstr(s: &str) -> PCWSTR {
    let mut wide: Vec<u16> = OsString::from(s).encode_wide().collect();
    wide.push(0); // Null terminate
    PCWSTR(wide.as_ptr())
}

pub fn dump_physical_memory(file_name: &str, path: &Path) {
    // Try to open the physical memory object (requires Administrator privileges)
    let physical_memory_handle: HANDLE = unsafe {
        CreateFileA(
            PCSTR(r"\\.\PhysicalMemory".as_ptr() as *const u8),
            GENERIC_READ.0 as u32,
            FILE_SHARE_READ, // Allow shared reading
            None, // No special security attributes
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ).expect("Fail to create file")
    };

    // If handle is invalid, just return (no error handling)
    if physical_memory_handle.is_invalid() {
        return;
    }

    // Attempt to create a file for the memory dump
    let mut dump_file = match File::create(path) {
        Ok(file) => file,
        Err(_) => return, // If file creation fails, exit the function
    };

    // Start reading memory in chunks (4096 bytes)
    let mut buffer = [0u8; 4096];
    let mut address: usize = 0;

    loop {
        let mut bytes_read: usize = 0;

        // Try reading from the physical memory
        let result = unsafe {
            ReadProcessMemory(
                physical_memory_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                Some(&mut bytes_read),
            )
        };

        // If reading memory fails, break out of the loop
        if !result.is_ok() {
            break;
        }

        // Write the read memory to the file
        if let Err(_) = dump_file.write_all(&buffer[..bytes_read]) {
            break; // If writing to file fails, exit the loop
        }

        // Move to the next memory chunk
        address += buffer.len();
    }

    // Close the handle after reading
    unsafe {
        CloseHandle(physical_memory_handle);
    }
}
