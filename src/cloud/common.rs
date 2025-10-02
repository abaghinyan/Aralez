//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::{SearchConfig, SectionConfig};

#[derive(Debug, Clone)]
pub struct ArtifactMeta {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub notes: Option<String>,
}

// ---------- Provider detection ----------
pub fn detect_provider(creds: &IndexMap<String, String>) -> Option<&'static str> {
    if creds.contains_key("AWS_ACCESS_KEY_ID") || creds.contains_key("AWS_REGION") {
        return Some("aws");
    }
    if creds.contains_key("AZURE_TENANT_ID")
        || creds.contains_key("AZURE_CLIENT_ID")
        || creds.contains_key("AZURE_CLIENT_SECRET")
    {
        return Some("azure");
    }
    if creds.contains_key("GCP_SERVICE_ACCOUNT_JSON") || creds.contains_key("GCP_PROJECT") {
        return Some("gcp");
    }
    None
}

pub fn resolve_output_path(
    base_dir: &Path,
    group_name: &str,
    entry_idx: usize,
    sc: &SearchConfig,
) -> PathBuf {
    if let Some(of) = &sc.output_file {
        let p = Path::new(of);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            base_dir.join(of)
        }
    } else {
        base_dir.join(format!("{}_{}.jsonl", group_name, entry_idx))
    }
}

// ---------- Time window helper (shared) ----------
pub fn window_ms(
    since: Option<&str>,
    until: Option<&str>,
    time_range: Option<&str>,
) -> Result<(i64, i64)> {
    use chrono::{DateTime, Duration, Utc};

    let now = Utc::now();
    let (start, end) = if let Some(tr) = time_range {
        let days = tr
            .strip_prefix('P')
            .and_then(|d| d.strip_suffix('D'))
            .and_then(|d| d.parse::<i64>().ok())
            .ok_or_else(|| anyhow!("Invalid timeRange '{}'", tr))?;
        (now - Duration::days(days), now)
    } else {
        let start = if let Some(s) = since {
            s.parse::<DateTime<Utc>>()
                .map_err(|e| anyhow!("Bad since (RFC3339 expected): {}", e))?
        } else {
            now - Duration::days(7)
        };
        let end = if let Some(u) = until {
            u.parse::<DateTime<Utc>>()
                .map_err(|e| anyhow!("Bad until (RFC3339 expected): {}", e))?
        } else {
            now
        };
        (start, end)
    };
    Ok((start.timestamp_millis(), end.timestamp_millis()))
}

// ---------- Preflights (dispatch to provider impls) ----------
pub async fn preflight(provider: &str, creds: &IndexMap<String, String>) -> Result<()> {
    match provider {
        "aws" => super::aws::preflight_aws(creds).await,
        "azure" => super::azure::preflight_azure(creds).await,
        "gcp" => super::gcp::preflight_gcp(creds).await,
        _ => Err(anyhow!("Unknown provider '{}'", provider)),
    }
}

// ---------- Common log collection utilities ----------

// Generic log collector trait for different cloud services
// Note: This trait is defined but not currently used in the implementation
// pub trait LogCollector {
//     async fn collect_logs(
//         &self,
//         params: &LogCollectionParams,
//         output_path: &Path,
//     ) -> Result<ArtifactMeta>;
// }

#[derive(Debug, Clone)]
pub struct LogCollectionParams {
    pub service: String,
    pub resource: Option<String>,
    pub time_range: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub filters: IndexMap<String, String>,
    pub max_results: Option<u32>,
    pub region: Option<String>,
}

impl LogCollectionParams {
    pub fn from_config_entry(entry: &str) -> Result<Self> {
        let (service, params_str) = entry
            .split_once(':')
            .map(|(s, p)| (s.trim(), Some(p.trim())))
            .unwrap_or((entry.trim(), None));

        let mut filters = IndexMap::new();
        let mut time_range = None;
        let mut since = None;
        let mut until = None;
        let mut resource = None;
        let mut max_results = None;
        let mut region = None;

        if let Some(params) = params_str {
            for pair in params.split(';').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                if let Some((key, value)) = pair.split_once('=') {
                    match key.trim() {
                        "timeRange" => time_range = Some(value.trim().to_string()),
                        "since" => since = Some(value.trim().to_string()),
                        "until" => until = Some(value.trim().to_string()),
                        "resource" => resource = Some(value.trim().to_string()),
                        "maxResults" => max_results = value.trim().parse().ok(),
                        "region" => region = Some(value.trim().to_string()),
                        _ => {
                            filters.insert(key.trim().to_string(), value.trim().to_string());
                        }
                    }
                }
            }
        }

        Ok(LogCollectionParams {
            service: service.to_string(),
            resource,
            time_range,
            since,
            until,
            filters,
            max_results,
            region,
        })
    }
}

/// Generic function to write logs to file with common formatting
pub fn write_logs_to_file<T: serde::Serialize>(
    logs: &[T],
    output_path: &Path,
    log_type: &str,
) -> Result<ArtifactMeta> {
    let mut file = File::create(output_path)?;
    let mut total_bytes = 0u64;

    for log in logs {
        let line = serde_json::to_vec(log)?;
        file.write_all(&line)?;
        file.write_all(b"\n")?;
        total_bytes += (line.len() + 1) as u64;
    }

    let meta = fs::metadata(output_path)?;
    Ok(ArtifactMeta {
        path: output_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("{} logs collected ({} entries, {} bytes)", 
            log_type, logs.len(), total_bytes)),
    })
}

/// Common error handling for cloud API calls
pub fn handle_cloud_error(error: &anyhow::Error, service: &str) -> anyhow::Error {
    let error_msg = error.to_string();
    
    if error_msg.contains("AccessDenied") || error_msg.contains("Forbidden") {
        anyhow::anyhow!("{}: Access denied - insufficient permissions", service)
    } else if error_msg.contains("InvalidClientTokenId") || error_msg.contains("ExpiredToken") {
        anyhow::anyhow!("{}: Invalid or expired credentials", service)
    } else if error_msg.contains("Throttling") || error_msg.contains("RateExceeded") {
        anyhow::anyhow!("{}: Rate limit exceeded - try again later", service)
    } else {
        anyhow::anyhow!("{}: {}", service, error_msg)
    }
}

/// Retry logic for transient errors
pub async fn retry_with_backoff<F, T, E>(
    mut operation: F,
    max_retries: u32,
    base_delay_ms: u64,
) -> Result<T>
where
    F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
    E: std::fmt::Display,
{
    let mut last_error = None;
    
    for attempt in 0..=max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries {
                    let delay = base_delay_ms * 2_u64.pow(attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }
    
    Err(anyhow::anyhow!(
        "Operation failed after {} retries. Last error: {}",
        max_retries,
        last_error.map(|e| e.to_string()).unwrap_or_else(|| "Unknown error".to_string())
    ))
}

// ---------- Stub outputs (kept for reference; not used in final dispatcher) ----------
pub async fn write_stub_outputs(
    section: &SectionConfig,
    output_dir: &str,
    provider: &str,
) -> Result<Vec<ArtifactMeta>> {
    fs::create_dir_all(output_dir)?;
    let out_dir = std::path::Path::new(output_dir);

    let mut results = Vec::new();
    let entries = match &section.entries {
        Some(e) => e,
        None => return Ok(results),
    };

    for (group, vec_cfg) in entries.iter() {
        for (idx, sc) in vec_cfg.iter().enumerate() {
            let out_path = resolve_output_path(out_dir, group, idx, sc);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = File::create(&out_path)
                .map_err(|e| anyhow!("Cannot create output file {:?}: {}", out_path, e))?;
            let _ = writeln!(
                f,
                "{{\"_note\":\"{} preflight ok; collection not implemented yet in this build\"}}",
                provider
            );
            let meta = fs::metadata(&out_path)?;
            results.push(ArtifactMeta {
                path: out_path.to_string_lossy().to_string(),
                bytes: meta.len() as u64,
                sha256: String::new(),
                notes: Some(format!("{} preflight ok; stub output", provider)),
            });
        }
    }
    Ok(results)
}