//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//
use std::ffi::CString;
use windows_sys::Win32::System::LibraryLoader::{BeginUpdateResourceA, EndUpdateResourceA, UpdateResourceA, EnumResourceNamesA, GetModuleHandleA, FindResourceA};
use windows_sys::Win32::System::LibraryLoader::{LoadResource, LockResource, SizeofResource};
use std::ffi::CStr;
use std::os::raw::c_void;
use std::io;
use std::fs;
use anyhow::Result;
use std::path::Path;
use std::env;

pub fn add_resource(
    file_path: &str,
    resource_name: &str,
    output_path: &str,
) -> io::Result<()> {
    // Path to the current executable
    let current_exe = env::current_exe().expect("Failed to get current executable path");
    // Check if the tool file exists
    if !Path::new(file_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("File {} not found", file_path),
        ));
    }

    // Load the tool file
    let tool_data = fs::read(file_path)?;

    // Copy the original executable to the output path
    fs::copy(current_exe, output_path)?;

    // Open the copied executable for updating resources
    let output_path_cstr = CString::new(output_path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid output path"))?;
    let handle = unsafe { BeginUpdateResourceA(output_path_cstr.as_ptr() as *const u8, 0) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }

    // Add the resource to the output executable
    let resource_name_cstr = CString::new(resource_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid resource name"))?;
    let result = unsafe {
        UpdateResourceA(
            handle,
            10 as *const u8, // Custom resource type
            resource_name_cstr.as_ptr() as *const u8,
            0x0409, // Language ID (US English)
            tool_data.as_ptr() as *const _,
            tool_data.len() as u32,
        )
    };
    if result == 0 {
        // Clean up and return the error
        unsafe { EndUpdateResourceA(handle, 1) };
        return Err(io::Error::last_os_error());
    }

    // Commit the resource updates
    let commit_result = unsafe { EndUpdateResourceA(handle, 0) };
    if commit_result == 0 {
        return Err(io::Error::last_os_error());
    }

    return Ok(());
}

pub fn remove_resource(resource_name: &str, output_path: &str) -> io::Result<()> {
    let resource_type: u16 = 10;

    // Check if the resource exists
    let resource_exists = unsafe {
        let exe_handle = GetModuleHandleA(std::ptr::null());
        if exe_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let resource_name_cstr = CString::new(resource_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid resource name"))?;

        !FindResourceA(
            exe_handle,
            resource_name_cstr.as_ptr() as *const u8,
            resource_type as *const u8,
        )
        .is_null()
    };

    if !resource_exists {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Resource `{}` of type `{}` not found in the executable.", resource_name, resource_type),
        ));
    }

    // Copy the current executable to the specified output file
    let current_exe = env::current_exe().expect("Failed to get current executable path");
    fs::copy(&current_exe, &output_path)?;

    // Open the executable for resource updates
    let output_cstr = CString::new(output_path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid output path"))?;
    let handle = unsafe { BeginUpdateResourceA(output_cstr.as_ptr() as *const u8, 0) }; 
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }

    // Remove the specified resource
    let resource_name_cstr = CString::new(resource_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid resource name"))?;
    let result = unsafe {
        UpdateResourceA(
            handle,
            resource_type as *const u8,
            resource_name_cstr.as_ptr() as *const u8,
            0x0409, // Language ID (US English)
            std::ptr::null_mut(), // Null pointer to remove the resource
            0,                    // Size is 0 when removing a resource
        )
    };
    if result == 0 {
        unsafe { EndUpdateResourceA(handle, 1) }; // Abort the update
        return Err(io::Error::last_os_error());
    }

    // Commit the resource update
    let commit_result = unsafe { EndUpdateResourceA(handle, 0) };
    if commit_result == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn list_resources(resource_type: u16) -> Result<Vec<String>, std::io::Error> {
    let mut resources = Vec::new();

    unsafe {
        // Get a handle to the current executable
        let exe_handle = GetModuleHandleA(std::ptr::null());
        if exe_handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        // Callback function to handle each resource name
        unsafe extern "system" fn callback(
            _: *mut c_void,
            _: *const u8,
            resource_name: *const u8,
            lparam: isize,
        ) -> i32 {
            // Cast lparam back to a mutable reference to the resources vector
            let resources = &mut *(lparam as *mut Vec<String>);
            if !resource_name.is_null() {
                // Convert the resource name to a Rust String
                let name = CStr::from_ptr(resource_name as *const i8).to_string_lossy().into_owned();
                resources.push(name);
            }
            1 // Continue enumeration
        }

        // Call EnumResourceNamesA to enumerate all resources of the given type
        let result = EnumResourceNamesA(
            exe_handle,
            resource_type as *const u8,
            Some(callback),
            &mut resources as *mut _ as isize,
        );

        if result == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(resources)
}

pub fn extract_resource(
    resource_name: &str,
) -> std::io::Result<Vec<u8>> {
    // The resource is a custom resources 
    let resource_type: u16 = 10;

    unsafe {
        // Get a handle to the current executable
        let module_handle = GetModuleHandleA(std::ptr::null());
        if module_handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        // Find the resource
        let resource_name_cstr = CString::new(resource_name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid resource name"))?;
        let resource = FindResourceA(
            module_handle,
            resource_name_cstr.as_ptr() as *const u8,
            resource_type as *const u8,
        );
        if resource.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        // Load the resource
        let resource_handle = LoadResource(module_handle, resource);
        if resource_handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        // Get a pointer to the resource data
        let resource_data = LockResource(resource_handle);
        if resource_data.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        // Get the size of the resource
        let resource_size = SizeofResource(module_handle, resource);
        if resource_size == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let data_slice = std::slice::from_raw_parts(resource_data as *const u8, resource_size as usize);

        return Ok(data_slice.to_vec());
    }
}