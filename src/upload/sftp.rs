// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use ssh2::Session;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

/// Upload the zip file via SFTP.
///
/// Authenticates via password or SSH key (key_path).
/// If neither is provided, attempts SSH agent authentication.
pub fn upload(
    zip_path: &str,
    host: &str,
    port: Option<u16>,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    remote_path: &str,
) -> Result<(), anyhow::Error> {
    let port = port.unwrap_or(22);
    let addr = format!("{}:{}", host, port);

    dprintln!("[INFO] Connecting to SFTP server: {}", addr);

    let tcp = TcpStream::connect(&addr)
        .map_err(|e| anyhow::anyhow!("Failed to connect to {}: {}", addr, e))?;

    let mut session = Session::new()
        .map_err(|e| anyhow::anyhow!("Failed to create SSH session: {}", e))?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|e| anyhow::anyhow!("SSH handshake failed: {}", e))?;

    // Authenticate
    if let Some(key) = key_path {
        session
            .userauth_pubkey_file(username, None, Path::new(key), None)
            .map_err(|e| anyhow::anyhow!("SSH key auth failed: {}", e))?;
    } else if let Some(pass) = password {
        session
            .userauth_password(username, pass)
            .map_err(|e| anyhow::anyhow!("SSH password auth failed: {}", e))?;
    } else {
        session
            .userauth_agent(username)
            .map_err(|e| anyhow::anyhow!("SSH agent auth failed: {}", e))?;
    }

    if !session.authenticated() {
        return Err(anyhow::anyhow!("SFTP authentication failed"));
    }

    let sftp = session
        .sftp()
        .map_err(|e| anyhow::anyhow!("Failed to start SFTP subsystem: {}", e))?;

    // Build remote file path
    let zip_file = Path::new(zip_path);
    let file_name = zip_file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid zip file path"))?
        .to_string_lossy();

    let remote_file_path = if remote_path.ends_with('/') {
        format!("{}{}", remote_path, file_name)
    } else {
        format!("{}/{}", remote_path, file_name)
    };

    // Read local file
    let mut local_file = std::fs::File::open(zip_path)?;
    let metadata = local_file.metadata()?;
    let file_size = metadata.len();

    // Create remote file
    let mut remote_file = sftp
        .create(Path::new(&remote_file_path))
        .map_err(|e| anyhow::anyhow!("Failed to create remote file '{}': {}", remote_file_path, e))?;

    // Transfer in chunks (8 MB)
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    let mut total_written: u64 = 0;

    loop {
        let bytes_read = local_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        remote_file.write_all(&buffer[..bytes_read])?;
        total_written += bytes_read as u64;
        dprintln!(
            "[INFO] SFTP upload progress: {}/{} bytes ({:.1}%)",
            total_written,
            file_size,
            (total_written as f64 / file_size as f64) * 100.0
        );
    }

    println!(
        "[INFO] Zip file uploaded via SFTP to {}:{}",
        host, remote_file_path
    );
    dprintln!(
        "[INFO] Zip file uploaded via SFTP to {}:{}",
        host, remote_file_path
    );

    Ok(())
}
