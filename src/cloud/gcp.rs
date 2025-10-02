//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;
use std::fs::{self, File};
use std::path::Path;
use std::io::Write;
use serde_json::json;

use crate::cloud::common::{resolve_output_path, window_ms, ArtifactMeta};
use crate::config::SectionConfig;

// ---------- GCP preflight (kept from your original) ----------
pub async fn preflight_gcp(creds: &IndexMap<String, String>) -> Result<()> {
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use pem::parse as parse_pem;
    use reqwest::StatusCode;
    use serde::Deserialize;

    let sa_json = creds
        .get("GCP_SERVICE_ACCOUNT_JSON")
        .ok_or_else(|| anyhow!("GCP_SERVICE_ACCOUNT_JSON missing"))?;
    let _project = creds
        .get("GCP_PROJECT")
        .ok_or_else(|| anyhow!("GCP_PROJECT missing"))?;

    let sa_content = match std::fs::read_to_string(sa_json) {
        Ok(s) => s,
        Err(_) => sa_json.clone(),
    };

    #[derive(Debug, Deserialize)]
    struct Sa {
        client_email: String,
        private_key: String,
        token_uri: Option<String>,
    }

    let sa: Sa = serde_json::from_str(&sa_content)
        .map_err(|e| anyhow!("GCP_SERVICE_ACCOUNT_JSON invalid: {}", e))?;

    let pem_block = parse_pem(sa.private_key.as_bytes())
        .map_err(|e| anyhow!("Failed to parse GCP private_key PEM: {}", e))?;
    let der = pem_block.contents();

    #[derive(serde::Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        scope: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
    }

    let now = Utc::now();
    let aud = sa
        .token_uri
        .as_deref()
        .unwrap_or("https://oauth2.googleapis.com/token");
    let scope = "https://www.googleapis.com/auth/cloud-platform.read-only";
    let claims = Claims {
        iss: &sa.client_email,
        scope,
        aud,
        iat: now.timestamp(),
        exp: (now + Duration::minutes(30)).timestamp(),
    };

    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_der(&der),
    )?;

    let form = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", jwt.as_str()),
    ];

    let resp = reqwest::Client::new()
        .post(aud)
        .form(&form)
        .send()
        .await
        .context("GCP OAuth token exchange failed")?;

    if resp.status() != StatusCode::OK {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if code == StatusCode::UNAUTHORIZED
            || body.contains("invalid_grant")
            || body.contains("invalid_client")
        {
            return Err(anyhow!("GCP credentials are invalid: {}", body));
        } else if code == StatusCode::FORBIDDEN || body.contains("permissionDenied") {
            return Err(anyhow!(
                "GCP credentials are valid but lack permissions: {}",
                body
            ));
        } else {
            return Err(anyhow!("GCP auth error ({}): {}", code, body));
        }
    }

    Ok(())
}

// ---------- OAuth access-token helper (service account) ----------
async fn gcp_access_token_from_sa(sa_json: &str, scope: &str) -> Result<String> {
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use pem::parse as parse_pem;
    use reqwest::StatusCode;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Sa {
        client_email: String,
        private_key: String,
        token_uri: Option<String>,
    }

    let sa: Sa = serde_json::from_str(sa_json)?;
    let pem = parse_pem(sa.private_key.as_bytes())?;
    let der = pem.contents();
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        scope: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
    }
    let now = Utc::now();
    let aud = sa
        .token_uri
        .as_deref()
        .unwrap_or("https://oauth2.googleapis.com/token");
    let claims = Claims {
        iss: &sa.client_email,
        scope,
        aud,
        iat: now.timestamp(),
        exp: (now + Duration::minutes(30)).timestamp(),
    };
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_der(&der),
    )?;
    let form = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", jwt.as_str()),
    ];
    let resp = reqwest::Client::new()
        .post(aud)
        .form(&form)
        .send()
        .await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!(
            "GCP token error: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    #[derive(serde::Deserialize)]
    struct Tok {
        access_token: String,
    }
    let t: Tok = resp.json().await?;
    Ok(t.access_token)
}

// ---------- Cloud Audit Logs collector ----------
async fn collect_audit_logs(
    creds: &IndexMap<String, String>,
    resource: &str, // "projects/ID" | "folders/ID" | "organizations/ID"
    filter: Option<String>,
    start_iso: &str,
    end_iso: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {

    let sa_path_or_inline = creds
        .get("GCP_SERVICE_ACCOUNT_JSON")
        .ok_or_else(|| anyhow!("GCP_SERVICE_ACCOUNT_JSON missing"))?;
    let sa_content =
        match std::fs::read_to_string(sa_path_or_inline) { Ok(s) => s, Err(_) => sa_path_or_inline.clone() };
    let token =
        gcp_access_token_from_sa(&sa_content, "https://www.googleapis.com/auth/logging.read")
            .await?;

    // Always timebox; add any extra filter if provided
    let mut f = format!("timestamp>=\"{}\" AND timestamp<=\"{}\"", start_iso, end_iso);
    if let Some(extra) = filter {
        f = format!("({}) AND ({})", f, extra);
    }

    let mut page_token: Option<String> = None;
    let client = reqwest::Client::new();
    let mut out = std::fs::File::create(out_path)?;
    let mut total = 0u64;

    loop {
        let body = json!({
            "resourceNames": [ resource ],
            "filter": f,
            "orderBy": "timestamp desc",
            "pageSize": 1000,
            "pageToken": page_token,
        });
        let resp = client
            .post("https://logging.googleapis.com/v2/entries:list")
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "GCP Logging error: {}",
                resp.text().await.unwrap_or_default()
            ));
        }
        let v: serde_json::Value = resp.json().await?;
        if let Some(arr) = v.get("entries").and_then(|e| e.as_array()) {
            for e in arr {
                let line = serde_json::to_vec(e)?;
                out.write_all(&line)?;
                out.write_all(b"\n")?;
                total += (line.len() + 1) as u64;
            }
        }
        page_token = v
            .get("nextPageToken")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
        if page_token.is_none() {
            break;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("gcp audit logs ({} bytes)", total)),
    })
}

// ---------- GCP: Security Command Center Findings ----------
async fn collect_security_command_center(
    creds: &IndexMap<String, String>,
    organization_id: &str,
    start_iso: &str,
    end_iso: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {

    let token = gcp_access_token_from_sa(
        creds.get("GCP_SERVICE_ACCOUNT_JSON").unwrap(),
        "https://www.googleapis.com/auth/cloud-platform.read-only",
    ).await?;

    let mut all_findings = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut url = format!(
            "https://securitycenter.googleapis.com/v1/organizations/{}/sources/-/findings",
            organization_id
        );

        let mut query_params = vec![
            ("pageSize".to_string(), "1000".to_string()),
            ("filter".to_string(), format!("state = \"ACTIVE\" AND createTime >= \"{}\" AND createTime <= \"{}\"", start_iso, end_iso)),
        ];

        if let Some(token) = page_token.take() {
            query_params.push(("pageToken".to_string(), token));
        }

        let query_string = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        url.push_str(&format!("?{}", query_string));

        let resp = reqwest::Client::new()
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "GCP Security Command Center API error: {}",
                resp.text().await.unwrap_or_default()
            ));
        }

        let v: serde_json::Value = resp.json().await?;
        if let Some(findings) = v.get("findings").and_then(|f| f.as_array()) {
            for finding in findings {
                all_findings.push(finding.clone());
            }
        }

        page_token = v
            .get("nextPageToken")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
        if page_token.is_none() {
            break;
        }
    }

    let mut out = File::create(out_path)?;
    let mut total_bytes = 0u64;

    for finding in &all_findings {
        let line = serde_json::to_vec(finding)?;
        out.write_all(&line)?;
        out.write_all(b"\n")?;
        total_bytes += (line.len() + 1) as u64;
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("gcp security command center ({} bytes)", total_bytes)),
    })
}

// ---------- GCP: Asset Inventory ----------
async fn collect_asset_inventory(
    creds: &IndexMap<String, String>,
    project_id: &str,
    asset_types: &[String],
    out_path: &Path,
) -> Result<ArtifactMeta> {

    let token = gcp_access_token_from_sa(
        creds.get("GCP_SERVICE_ACCOUNT_JSON").unwrap(),
        "https://www.googleapis.com/auth/cloud-platform.read-only",
    ).await?;

    let mut all_assets = Vec::new();

    for asset_type in asset_types {
        let mut page_token: Option<String> = None;

        loop {
            let mut url = format!(
                "https://cloudasset.googleapis.com/v1/projects/{}/assets",
                project_id
            );

            let mut query_params = vec![
                ("assetTypes".to_string(), asset_type.clone()),
                ("pageSize".to_string(), "1000".to_string()),
            ];

            if let Some(token) = page_token.take() {
                query_params.push(("pageToken".to_string(), token));
            }

            let query_string = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");

            url.push_str(&format!("?{}", query_string));

            let resp = reqwest::Client::new()
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await?;

            if !resp.status().is_success() {
                return Err(anyhow!(
                    "GCP Cloud Asset API error: {}",
                    resp.text().await.unwrap_or_default()
                ));
            }

            let v: serde_json::Value = resp.json().await?;
            if let Some(assets) = v.get("assets").and_then(|a| a.as_array()) {
                for asset in assets {
                    all_assets.push(asset.clone());
                }
            }

            page_token = v
                .get("nextPageToken")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
            if page_token.is_none() {
                break;
            }
        }
    }

    let mut out = File::create(out_path)?;
    let mut total_bytes = 0u64;

    for asset in &all_assets {
        let line = serde_json::to_vec(asset)?;
        out.write_all(&line)?;
        out.write_all(b"\n")?;
        total_bytes += (line.len() + 1) as u64;
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("gcp asset inventory ({} bytes)", total_bytes)),
    })
}

// ---------- GCP: Cloud SQL Logs ----------
async fn collect_cloudsql_logs(
    creds: &IndexMap<String, String>,
    project_id: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    let token = gcp_access_token_from_sa(
        creds.get("GCP_SERVICE_ACCOUNT_JSON").unwrap(),
        "https://www.googleapis.com/auth/cloud-platform.read-only",
    ).await?;

    let mut all_logs = Vec::new();

    // Get Cloud SQL instances
    let instances_resp = reqwest::Client::new()
        .get(&format!(
            "https://sqladmin.googleapis.com/v1/projects/{}/instances",
            project_id
        ))
        .bearer_auth(&token)
        .send()
        .await?;

    if instances_resp.status().is_success() {
        let instances: serde_json::Value = instances_resp.json().await?;
        if let Some(instances_list) = instances.get("items").and_then(|i| i.as_array()) {
            for instance in instances_list {
                if let Some(instance_name) = instance.get("name").and_then(|n| n.as_str()) {
                    // Get logs for this instance
                    let logs_resp = reqwest::Client::new()
                        .get(&format!(
                            "https://sqladmin.googleapis.com/v1/projects/{}/instances/{}/logs",
                            project_id, instance_name
                        ))
                        .bearer_auth(&token)
                        .send()
                        .await?;

                    if logs_resp.status().is_success() {
                        let logs: serde_json::Value = logs_resp.json().await?;
                        if let Some(logs_list) = logs.get("items").and_then(|l| l.as_array()) {
                            for log in logs_list {
                                all_logs.push(log.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    let mut out = File::create(out_path)?;
    let mut total_bytes = 0u64;

    for log in &all_logs {
        let line = serde_json::to_vec(log)?;
        out.write_all(&line)?;
        out.write_all(b"\n")?;
        total_bytes += (line.len() + 1) as u64;
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("gcp cloud sql logs ({} bytes)", total_bytes)),
    })
}

// ---------- dispatcher ----------
pub async fn collect_entries(
    section: &SectionConfig,
    output_dir: &str,
    creds: &IndexMap<String, String>,
) -> Result<Vec<ArtifactMeta>> {
    fs::create_dir_all(output_dir)?;
    let out_dir = Path::new(output_dir);
    let mut results = vec![];
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
            let objs = sc.objects.clone().unwrap_or_default();

            let mut notes = vec![];
            let mut total_bytes = 0u64;

            for o in objs {
                let (verb, params) = o
                    .split_once(':')
                    .map(|(v, r)| (v.trim(), Some(r.trim())))
                    .unwrap_or((o.trim(), None));
                let mut time_range: Option<String> = None;
                let mut since: Option<String> = None;
                let mut until: Option<String> = None;
                let mut resource = String::new();
                let mut flt: Option<String> = None;
                let mut organization_id = String::new();
                let mut project_id = String::new();
                let mut asset_types: Vec<String> = vec![];

                if let Some(rest) = params {
                    for pair in rest.split(';').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                        if let Some((k, v)) = pair.split_once('=') {
                            match k {
                                "timeRange" => time_range = Some(v.to_string()),
                                "since" => since = Some(v.to_string()),
                                "until" => until = Some(v.to_string()),
                                "resource" => resource = v.to_string(),
                                "filter" => flt = Some(v.to_string()),
                                "organizationId" => organization_id = v.to_string(),
                                "projectId" => project_id = v.to_string(),
                                "assetTypes" => {
                                    asset_types = v.split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
                                }
                                _ => {}
                            }
                        }
                    }
                }
                let (start_ms, end_ms) =
                    window_ms(since.as_deref(), until.as_deref(), time_range.as_deref())?;
                let start_iso = chrono::DateTime::from_timestamp_millis(start_ms)
                    .unwrap()
                    .to_rfc3339();
                let end_iso = chrono::DateTime::from_timestamp_millis(end_ms)
                    .unwrap()
                    .to_rfc3339();

                match verb.to_ascii_lowercase().as_str() {
                    "gcpauditlogs" => {
                        if resource.is_empty() {
                            return Err(anyhow!(
                                "GcpAuditLogs requires resource=projects/ID|folders/ID|organizations/ID"
                            ));
                        }
                        let meta = collect_audit_logs(
                            creds,
                            &resource,
                            flt.clone(),
                            &start_iso,
                            &end_iso,
                            &out_path,
                        )
                        .await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "gcpsecuritycommandcenter" => {
                        if organization_id.is_empty() {
                            return Err(anyhow!("GcpSecurityCommandCenter requires organizationId"));
                        }
                        let meta = collect_security_command_center(
                            creds,
                            &organization_id,
                            &start_iso,
                            &end_iso,
                            &out_path,
                        )
                        .await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "gcpassetinventory" => {
                        if project_id.is_empty() {
                            return Err(anyhow!("GcpAssetInventory requires projectId"));
                        }
                        let asset_types = if asset_types.is_empty() {
                            vec!["*".to_string()]
                        } else {
                            asset_types
                        };
                        let meta = collect_asset_inventory(creds, &project_id, &asset_types, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "gcpcloudsql" => {
                        if project_id.is_empty() {
                            return Err(anyhow!("GcpCloudSql requires projectId"));
                        }
                        let meta = collect_cloudsql_logs(creds, &project_id, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    _ => { /* ignore unknown for portability */ }
                }
            }

            let meta = fs::metadata(&out_path)?;
            results.push(ArtifactMeta {
                path: out_path.to_string_lossy().to_string(),
                bytes: total_bytes.max(meta.len() as u64),
                sha256: String::new(),
                notes: Some(format!("gcp: {}", notes.join(" | "))),
            });
        }
    }
    Ok(results)
}
