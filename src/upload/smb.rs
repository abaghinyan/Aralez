// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use std::path::Path;
use std::process::Command;

/// Upload the zip file to an SMB share.
///
/// On Linux, uses `smbclient`. On Windows, uses `net use` + `copy`.
///
/// `share` format: `//server/share/path` or `\\server\share\path`
#[allow(unused_variables)]
pub fn upload(
    zip_path: &str,
    share: &str,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<(), anyhow::Error> {
    let zip_file = Path::new(zip_path);
    let file_name = zip_file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid zip file path"))?
        .to_string_lossy();

    #[cfg(target_os = "linux")]
    {
        upload_linux(zip_path, &file_name, share, username, password, domain)
    }

    #[cfg(target_os = "windows")]
    {
        upload_windows(zip_path, share, username, password, domain)
    }
}

#[cfg(target_os = "linux")]
fn upload_linux(
    zip_path: &str,
    file_name: &str,
    share: &str,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<(), anyhow::Error> {
    // Parse share path: //server/sharename/optional/subpath
    let normalized = share.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .trim_start_matches('/')
        .splitn(3, '/')
        .collect();

    if parts.len() < 2 {
        return Err(anyhow::anyhow!(
            "Invalid SMB share format. Expected: //server/share[/path]"
        ));
    }

    let server = parts[0];
    let share_name = parts[1];
    let remote_subdir = if parts.len() > 2 { parts[2] } else { "" };

    let service = format!("//{}/{}", server, share_name);

    let mut cmd = Command::new("smbclient");
    cmd.arg(&service);

    if let Some(user) = username {
        cmd.arg("-U");
        if let Some(pass) = password {
            if let Some(dom) = domain {
                cmd.arg(format!("{}/{}%{}", dom, user, pass));
            } else {
                cmd.arg(format!("{}%{}", user, pass));
            }
        } else {
            cmd.arg(user);
            cmd.arg("-N"); // No password
        }
    } else {
        cmd.arg("-N"); // Anonymous
    }

    // Build smbclient commands: cd to subdir (if any) then put the file
    let mut smb_commands = String::new();
    if !remote_subdir.is_empty() {
        // Create directory tree if needed
        let mut accumulated = String::new();
        for segment in remote_subdir.split('/').filter(|s| !s.is_empty()) {
            accumulated.push_str(segment);
            smb_commands.push_str(&format!("mkdir {}\n", accumulated));
            accumulated.push('/');
        }
        smb_commands.push_str(&format!("cd {}\n", remote_subdir));
    }
    smb_commands.push_str(&format!("put {} {}\n", zip_path, file_name));
    smb_commands.push_str("quit\n");

    cmd.arg("-c").arg(&smb_commands);

    dprintln!("[INFO] Uploading to SMB share: {}", share);

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "smbclient failed: {}",
            stderr.trim()
        ));
    }

    println!("[INFO] Zip file uploaded to SMB share: {}/{}", share, file_name);
    dprintln!("[INFO] Zip file uploaded to SMB share: {}/{}", share, file_name);

    Ok(())
}

#[cfg(target_os = "windows")]
fn upload_windows(
    zip_path: &str,
    share: &str,
    username: Option<&str>,
    password: Option<&str>,
    _domain: Option<&str>,
) -> Result<(), anyhow::Error> {
    let normalized = share.replace('/', "\\");

    // If credentials are provided, map the share first
    if username.is_some() || password.is_some() {
        let mut net_cmd = Command::new("net");
        net_cmd.arg("use").arg(&normalized);

        if let Some(pass) = password {
            net_cmd.arg(pass);
        }
        if let Some(user) = username {
            net_cmd.arg(format!("/user:{}", user));
        }

        let net_output = net_cmd.output()?;
        if !net_output.status.success() {
            let stderr = String::from_utf8_lossy(&net_output.stderr);
            dprintln!("[WARN] net use may have failed (share might already be mapped): {}", stderr.trim());
        }
    }

    // Copy the file
    let dest = format!("{}\\{}", normalized.trim_end_matches('\\'), Path::new(zip_path).file_name().unwrap().to_string_lossy());
    let copy_output = Command::new("cmd")
        .args(["/C", "copy", "/Y", zip_path, &dest])
        .output()?;

    if !copy_output.status.success() {
        let stderr = String::from_utf8_lossy(&copy_output.stderr);
        return Err(anyhow::anyhow!(
            "SMB copy failed: {}",
            stderr.trim()
        ));
    }

    println!("[INFO] Zip file uploaded to SMB share: {}", dest);
    dprintln!("[INFO] Zip file uploaded to SMB share: {}", dest);

    Ok(())
}
