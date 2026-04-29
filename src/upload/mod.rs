// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

pub mod folder;

#[cfg(feature = "upload-sftp")]
pub mod sftp;

#[cfg(feature = "upload-s3")]
pub mod s3;

pub mod smb;

use crate::config::{OutputConfig, OutputDestination};
use std::path::Path;

/// Optional S3-specific overrides from CLI arguments.
#[allow(dead_code)]
#[derive(Default, Clone)]
pub struct S3Overrides {
    pub endpoint: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
}

/// Upload the zip file to all configured destinations.
/// `cli_output` is an optional CLI override (e.g. --output /path or s3://bucket/prefix).
/// `s3_overrides` contains optional CLI-provided S3 endpoint and credentials.
pub fn dispatch(
    zip_path: &str,
    config_output: &Option<OutputConfig>,
    cli_output: Option<&str>,
    s3_overrides: &S3Overrides,
) -> Result<(), anyhow::Error> {
    let zip_file = Path::new(zip_path);
    if !zip_file.exists() {
        return Err(anyhow::anyhow!(
            "[ERROR] Zip file '{}' not found for upload",
            zip_path
        ));
    }

    // Handle CLI --output override
    if let Some(output_str) = cli_output {
        let dest = parse_cli_output(output_str)?;
        upload_to_destination(zip_path, &dest, s3_overrides)?;
        return Ok(());
    }

    // Handle config-based destinations
    if let Some(output_config) = config_output {
        if let Some(destinations) = &output_config.destinations {
            for dest in destinations {
                if let Err(e) = upload_to_destination(zip_path, dest, s3_overrides) {
                    eprintln!("[ERROR] Upload failed for destination: {}", e);
                    dprintln!("[ERROR] Upload failed for destination: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Parse a CLI output string into an OutputDestination.
///
/// Supported formats:
///   s3://bucket/prefix
///   smb://server/share/path
///   sftp://user@host:port/remote/path
///   sftp://user@host/remote/path
///   /local/path (or any path without a scheme)
fn parse_cli_output(output: &str) -> Result<OutputDestination, anyhow::Error> {
    if output.starts_with("s3://") {
        let rest = &output[5..]; // strip "s3://"
        let (bucket, prefix) = match rest.find('/') {
            Some(pos) => (rest[..pos].to_string(), Some(rest[pos + 1..].to_string())),
            None => (rest.to_string(), None),
        };
        Ok(OutputDestination::S3 {
            bucket,
            prefix,
            region: None,
            endpoint: None,
            access_key: None,
            secret_key: None,
        })
    } else if output.starts_with("smb://") {
        let rest = &output[4..]; // Keep the "//" prefix → "//server/share/path"
        Ok(OutputDestination::Smb {
            share: rest.to_string(),
            username: None,
            password: None,
            domain: None,
        })
    } else if output.starts_with("sftp://") {
        let rest = &output[7..]; // strip "sftp://"
        // Format: user@host:port/path or user@host/path
        let (user_host, remote_path) = rest
            .find('/')
            .map(|pos| (&rest[..pos], rest[pos..].to_string()))
            .unwrap_or((rest, "/".to_string()));

        let (user_part, host_port) = user_host
            .rsplit_once('@')
            .ok_or_else(|| anyhow::anyhow!("SFTP URL must contain user@host"))?;

        let (host, port) = match host_port.find(':') {
            Some(pos) => (
                host_port[..pos].to_string(),
                Some(
                    host_port[pos + 1..]
                        .parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("Invalid SFTP port"))?,
                ),
            ),
            None => (host_port.to_string(), None),
        };

        Ok(OutputDestination::Sftp {
            host,
            port,
            username: user_part.to_string(),
            password: None,
            key_path: None,
            remote_path,
        })
    } else {
        // Treat as a local/network folder path
        Ok(OutputDestination::Folder {
            path: output.to_string(),
        })
    }
}

fn upload_to_destination(
    zip_path: &str,
    dest: &OutputDestination,
    _s3_overrides: &S3Overrides,
) -> Result<(), anyhow::Error> {
    match dest {
        OutputDestination::Folder { path } => {
            folder::upload(zip_path, path)?;
        }
        OutputDestination::S3 {
            bucket,
            prefix,
            region,
            endpoint,
            access_key,
            secret_key,
        } => {
            #[cfg(feature = "upload-s3")]
            {
                // CLI overrides take precedence over config values
                let effective_endpoint = _s3_overrides.endpoint.as_deref().or(endpoint.as_deref());
                let effective_ak = _s3_overrides.access_key.as_deref().or(access_key.as_deref());
                let effective_sk = _s3_overrides.secret_key.as_deref().or(secret_key.as_deref());

                s3::upload(
                    zip_path,
                    bucket,
                    prefix.as_deref(),
                    region.as_deref(),
                    effective_endpoint,
                    effective_ak,
                    effective_sk,
                )?;
            }
            #[cfg(not(feature = "upload-s3"))]
            {
                let _ = (bucket, prefix, region, endpoint, access_key, secret_key);
                return Err(anyhow::anyhow!(
                    "S3 upload is not available. Rebuild with: cargo build --features upload-s3"
                ));
            }
        }
        OutputDestination::Smb {
            share,
            username,
            password,
            domain,
        } => {
            smb::upload(
                zip_path,
                share,
                username.as_deref(),
                password.as_deref(),
                domain.as_deref(),
            )?;
        }
        OutputDestination::Sftp {
            host,
            port,
            username,
            password,
            key_path,
            remote_path,
        } => {
            #[cfg(feature = "upload-sftp")]
            {
                sftp::upload(
                    zip_path,
                    host,
                    *port,
                    username,
                    password.as_deref(),
                    key_path.as_deref(),
                    remote_path,
                )?;
            }
            #[cfg(not(feature = "upload-sftp"))]
            {
                let _ = (host, port, username, password, key_path, remote_path);
                return Err(anyhow::anyhow!(
                    "SFTP upload is not available. Rebuild with: cargo build --features upload-sftp"
                ));
            }
        }
    }
    Ok(())
}
