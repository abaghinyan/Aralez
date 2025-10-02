//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;
use std::fs;
use std::path::Path;
use std::io::Write;

use crate::cloud::common::{resolve_output_path, window_ms, ArtifactMeta};
use crate::config::SectionConfig;

// ---------- Azure preflight ----------
pub async fn preflight_azure(creds: &IndexMap<String, String>) -> Result<()> {
    use reqwest::StatusCode;

    let tenant_id = creds
        .get("AZURE_TENANT_ID")
        .ok_or_else(|| anyhow!("AZURE_TENANT_ID missing"))?;
    let client_id = creds
        .get("AZURE_CLIENT_ID")
        .ok_or_else(|| anyhow!("AZURE_CLIENT_ID missing"))?;
    let client_secret = creds
        .get("AZURE_CLIENT_SECRET")
        .ok_or_else(|| anyhow!("AZURE_CLIENT_SECRET missing"))?;

    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let scope = "https://management.azure.com/.default";
    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("scope", scope),
    ];

    let resp = reqwest::Client::new()
        .post(&url)
        .form(&form)
        .send()
        .await
        .context("Azure token request failed")?;

    if resp.status() != StatusCode::OK {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if code == StatusCode::UNAUTHORIZED
            || body.contains("invalid_client")
            || body.contains("unauthorized_client")
        {
            return Err(anyhow!("Azure credentials are invalid: {}", body));
        } else if code == StatusCode::FORBIDDEN
            || body.contains("insufficient privileges")
            || body.contains("insufficient_access")
        {
            return Err(anyhow!(
                "Azure credentials are valid but lack permissions: {}",
                body
            ));
        } else {
            return Err(anyhow!("Azure auth error ({}): {}", code, body));
        }
    }

    Ok(())
}

// ---------- token helpers ----------
#[derive(Clone)]
struct AzureToken {
    access_token: String,
    _expires_on_utc: chrono::DateTime<chrono::Utc>,
}

async fn token_client_credentials(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<AzureToken> {
    use reqwest::StatusCode;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Resp {
        access_token: String,
        expires_in: i64,
    }
    let url = format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant_id);
    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", scope),
    ];
    let resp = reqwest::Client::new().post(&url).form(&form).send().await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!(
            "Azure token error: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: Resp = resp.json().await?;
    Ok(AzureToken {
        access_token: body.access_token,
        _expires_on_utc: chrono::Utc::now() + chrono::Duration::seconds(body.expires_in),
    })
}

async fn get_arm_token(creds: &IndexMap<String, String>) -> Result<AzureToken> {
    let tenant = creds
        .get("AZURE_TENANT_ID")
        .ok_or_else(|| anyhow!("AZURE_TENANT_ID missing"))?;
    let cid = creds
        .get("AZURE_CLIENT_ID")
        .ok_or_else(|| anyhow!("AZURE_CLIENT_ID missing"))?;
    let sec = creds
        .get("AZURE_CLIENT_SECRET")
        .ok_or_else(|| anyhow!("AZURE_CLIENT_SECRET missing"))?;
    token_client_credentials(tenant, cid, sec, "https://management.azure.com/.default").await
}
async fn get_graph_token(creds: &IndexMap<String, String>) -> Result<AzureToken> {
    let tenant = creds
        .get("AZURE_TENANT_ID")
        .ok_or_else(|| anyhow!("AZURE_TENANT_ID missing"))?;
    let cid = creds
        .get("AZURE_CLIENT_ID")
        .ok_or_else(|| anyhow!("AZURE_CLIENT_ID missing"))?;
    let sec = creds
        .get("AZURE_CLIENT_SECRET")
        .ok_or_else(|| anyhow!("AZURE_CLIENT_SECRET missing"))?;
    token_client_credentials(tenant, cid, sec, "https://graph.microsoft.com/.default").await
}

// ---------- collectors ----------
async fn collect_activity_logs(
    creds: &IndexMap<String, String>,
    subscriptions: &[String],
    start_iso: &str,
    end_iso: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use serde_json::Value;

    let tok = get_arm_token(creds).await?;
    let client = reqwest::Client::new();
    let mut total = 0u64;
    let mut out = std::fs::File::create(out_path)?;

    for sub in subscriptions {
        let base = format!("https://management.azure.com/subscriptions/{}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01", sub);
        let filter = format!("eventTimestamp ge '{}' and eventTimestamp le '{}'", start_iso, end_iso);
        let mut url = format!("{}&$filter={}", base, urlencoding::encode(&filter));

        loop {
            let resp = client
                .get(&url)
                .bearer_auth(&tok.access_token)
                .send()
                .await?;
            if !resp.status().is_success() {
                return Err(anyhow!(
                    "Azure Activity API error: {}",
                    resp.text().await.unwrap_or_default()
                ));
            }
            let v: Value = resp.json().await?;
            if let Some(arr) = v.get("value").and_then(|x| x.as_array()) {
                for ev in arr {
                    let line = serde_json::to_vec(ev)?;
                    out.write_all(&line)?;
                    out.write_all(b"\n")?;
                    total += (line.len() + 1) as u64;
                }
            }
            if let Some(next) = v.get("nextLink").and_then(|n| n.as_str()) {
                url = next.to_string();
            } else {
                break;
            }
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("azure activity logs ({} bytes)", total)),
    })
}

async fn collect_entra_logs(
    creds: &IndexMap<String, String>,
    which: &str, // "signins" | "audit"
    start_iso: &str,
    end_iso: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use serde_json::Value;
    let tok = get_graph_token(creds).await?;
    let client = reqwest::Client::new();

    let (path, ts_field) = match which {
        "signins" => ("/v1.0/auditLogs/signIns", "createdDateTime"),
        "audit" => ("/v1.0/auditLogs/directoryAudits", "activityDateTime"),
        _ => return Err(anyhow!("unknown entra log kind")),
    };

    let filter = format!(
        "{} ge {} and {} le {}",
        ts_field, start_iso, ts_field, end_iso
    );
    let mut url = format!(
        "https://graph.microsoft.com{}?$top=100&$filter={}",
        path,
        urlencoding::encode(&filter)
    );

    let mut total = 0u64;
    let mut out = std::fs::File::create(out_path)?;

    loop {
        let resp = client.get(&url).bearer_auth(&tok.access_token).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "Graph API error: {}",
                resp.text().await.unwrap_or_default()
            ));
        }
        let v: Value = resp.json().await?;
        if let Some(arr) = v.get("value").and_then(|x| x.as_array()) {
            for ev in arr {
                let line = serde_json::to_vec(ev)?;
                out.write_all(&line)?;
                out.write_all(b"\n")?;
                total += (line.len() + 1) as u64;
            }
        }
        if let Some(next) = v.get("@odata.nextLink").and_then(|x| x.as_str()) {
            url = next.to_string();
        } else {
            break;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("azure entra {} logs ({} bytes)", which, total)),
    })
}

// ---------- Azure: Security Center Alerts ----------
async fn collect_security_center_alerts(
    creds: &IndexMap<String, String>,
    subscriptions: &[String],
    _start_iso: &str,
    _end_iso: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use serde_json::Value;

    let tok = get_arm_token(creds).await?;
    let client = reqwest::Client::new();
    let mut total = 0u64;
    let mut out = std::fs::File::create(out_path)?;

    for sub in subscriptions {
        let base = format!("https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/alerts?api-version=2022-01-01", sub);
        let mut url = base;

        loop {
            let resp = client
                .get(&url)
                .bearer_auth(&tok.access_token)
                .send()
                .await?;
            if !resp.status().is_success() {
                return Err(anyhow!(
                    "Azure Security Center API error: {}",
                    resp.text().await.unwrap_or_default()
                ));
            }
            let v: Value = resp.json().await?;
            if let Some(arr) = v.get("value").and_then(|x| x.as_array()) {
                for alert in arr {
                    let line = serde_json::to_vec(alert)?;
                    out.write_all(&line)?;
                    out.write_all(b"\n")?;
                    total += (line.len() + 1) as u64;
                }
            }
            if let Some(next) = v.get("nextLink").and_then(|n| n.as_str()) {
                url = next.to_string();
            } else {
                break;
            }
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("azure security center alerts ({} bytes)", total)),
    })
}

// ---------- Azure: Key Vault Logs ----------
async fn collect_keyvault_logs(
    creds: &IndexMap<String, String>,
    vault_name: &str,
    resource_group: &str,
    subscription: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use serde_json::Value;

    let tok = get_arm_token(creds).await?;
    let client = reqwest::Client::new();
    let mut total = 0u64;
    let mut out = std::fs::File::create(out_path)?;

    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault/vaults/{}/accessPolicies?api-version=2022-07-01",
        subscription, resource_group, vault_name
    );

    let resp = client
        .get(&url)
        .bearer_auth(&tok.access_token)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Azure Key Vault API error: {}",
            resp.text().await.unwrap_or_default()
        ));
    }

    let v: Value = resp.json().await?;
    if let Some(access_policies) = v.get("accessPolicies").and_then(|x| x.as_array()) {
        for policy in access_policies {
            let line = serde_json::to_vec(policy)?;
            out.write_all(&line)?;
            out.write_all(b"\n")?;
            total += (line.len() + 1) as u64;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("azure key vault logs ({} bytes)", total)),
    })
}

// ---------- Azure: Resource Graph Queries ----------
async fn collect_resource_graph(
    creds: &IndexMap<String, String>,
    query: &str,
    subscriptions: &[String],
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use serde_json::{json, Value};

    let tok = get_arm_token(creds).await?;
    let client = reqwest::Client::new();
    let mut total = 0u64;
    let mut out = std::fs::File::create(out_path)?;

    let body = json!({
        "query": query,
        "subscriptions": subscriptions
    });

    let resp = client
        .post("https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01")
        .bearer_auth(&tok.access_token)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Azure Resource Graph API error: {}",
            resp.text().await.unwrap_or_default()
        ));
    }

    let v: Value = resp.json().await?;
    if let Some(data) = v.get("data").and_then(|x| x.as_array()) {
        for resource in data {
            let line = serde_json::to_vec(resource)?;
            out.write_all(&line)?;
            out.write_all(b"\n")?;
            total += (line.len() + 1) as u64;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("azure resource graph ({} bytes)", total)),
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
                let mut subs: Option<Vec<String>> = None;
                let mut vault_name: Option<String> = None;
                let mut resource_group: Option<String> = None;
                let mut subscription: Option<String> = None;
                let mut query: Option<String> = None;

                if let Some(rest) = params {
                    for pair in rest.split(';').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                        if let Some((k, v)) = pair.split_once('=') {
                            match k {
                                "timeRange" => time_range = Some(v.to_string()),
                                "since" => since = Some(v.to_string()),
                                "until" => until = Some(v.to_string()),
                                "subscriptions" => {
                                    subs = Some(
                                        v.split(',')
                                            .map(|s| s.trim().to_string())
                                            .collect(),
                                    )
                                }
                                "vaultName" => vault_name = Some(v.to_string()),
                                "resourceGroup" => resource_group = Some(v.to_string()),
                                "subscription" => subscription = Some(v.to_string()),
                                "query" => query = Some(v.to_string()),
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
                    "azureactivity" => {
                        let subs = subs.ok_or_else(|| {
                            anyhow!("AzureActivity requires subscriptions=comma,separated,ids")
                        })?;
                        let meta =
                            collect_activity_logs(creds, &subs, &start_iso, &end_iso, &out_path)
                                .await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "azureentrasignins" => {
                        let meta =
                            collect_entra_logs(creds, "signins", &start_iso, &end_iso, &out_path)
                                .await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "azureentraaudit" => {
                        let meta =
                            collect_entra_logs(creds, "audit", &start_iso, &end_iso, &out_path)
                                .await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "azuresecuritycenter" => {
                        let subs = subs.unwrap_or_else(|| vec!["*".to_string()]);
                        let meta = collect_security_center_alerts(creds, &subs, &start_iso, &end_iso, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "azurekeyvault" => {
                        let vault = vault_name.ok_or_else(|| anyhow!("vaultName required"))?;
                        let rg = resource_group.ok_or_else(|| anyhow!("resourceGroup required"))?;
                        let sub = subscription.ok_or_else(|| anyhow!("subscription required"))?;
                        let meta = collect_keyvault_logs(creds, &vault, &rg, &sub, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "azureresourcegraph" => {
                        let subs = subs.unwrap_or_else(|| vec!["*".to_string()]);
                        let query_str = query.unwrap_or_else(|| "Resources | limit 1000".to_string());
                        let meta = collect_resource_graph(creds, &query_str, &subs, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    _ => { /* ignore unknown for portability */ }
                }
            }

            results.push(ArtifactMeta {
                path: out_path.to_string_lossy().to_string(),
                bytes: total_bytes as u64,
                sha256: String::new(),
                notes: Some(format!("azure: {}", notes.join(" | "))),
            });
        }
    }
    Ok(results)
}
