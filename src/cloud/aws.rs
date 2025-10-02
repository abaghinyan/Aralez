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
use std::io::{Read, Write};
use std::path::Path;

use crate::cloud::common::{resolve_output_path, window_ms, ArtifactMeta};
use crate::config::SectionConfig;

// ---------- AWS preflight: STS GetCallerIdentity ----------
pub async fn preflight_aws(creds: &IndexMap<String, String>) -> Result<()> {
    use aws_config::meta::region::RegionProviderChain;
    use aws_config::{BehaviorVersion, Region};
    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_credential_types::Credentials;
    use aws_sdk_sts as sts;

    let access_key = creds
        .get("AWS_ACCESS_KEY_ID")
        .ok_or_else(|| anyhow!("AWS_ACCESS_KEY_ID missing"))?;
    let secret = creds
        .get("AWS_SECRET_ACCESS_KEY")
        .ok_or_else(|| anyhow!("AWS_SECRET_ACCESS_KEY missing"))?;
    let region = creds
        .get("AWS_REGION")
        .cloned()
        .unwrap_or_else(|| "us-east-1".to_string());
    let session = creds.get("AWS_SESSION_TOKEN").cloned();

    let creds = Credentials::new(access_key, secret, session, None, "aralez_static");
    let rp = RegionProviderChain::first_try(Region::new(region));

    let conf = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(SharedCredentialsProvider::new(creds))
        .region(rp)
        .load()
        .await;

    let client = sts::Client::new(&conf);
    match client.get_caller_identity().send().await {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("AccessDenied")
                || msg.contains("Not authorized")
                || msg.contains("not authorized")
                || msg.contains("AccessDeniedException")
            {
                Err(anyhow!(
                    "AWS credentials are valid but lack permissions (AccessDenied): {}",
                    msg
                ))
            } else if msg.contains("ExpiredToken") || msg.contains("InvalidClientTokenId") {
                Err(anyhow!("AWS credentials are invalid/expired: {}", msg))
            } else {
                Err(anyhow!("AWS credential/auth error: {}", msg))
            }
        }
    }
}

// ---------- AWS: CloudTrail Event History (LookupEvents) ----------
async fn write_lookup_events_jsonl(
    client: &aws_sdk_cloudtrail::Client,
    object: &str,
    out: &mut File,
) -> Result<u64> {
    use aws_sdk_cloudtrail::error::SdkError;
    use aws_sdk_cloudtrail::types::{LookupAttribute, LookupAttributeKey};
    use aws_smithy_types::error::metadata::ProvideErrorMetadata;
    use aws_smithy_types::DateTime as AwsDateTime;
    use chrono::{Duration, Utc};

    fn looks_like_cred_or_perm(msg: &str) -> bool {
        msg.contains("AccessDenied")
            || msg.contains("UnrecognizedClient")
            || msg.contains("InvalidClientTokenId")
            || msg.contains("SignatureDoesNotMatch")
            || msg.contains("ExpiredToken")
            || msg.contains("Not authorized")
            || msg.contains("not authorized")
            || msg.contains("AccessDeniedException")
    }
    fn is_transient_code(code: Option<&str>) -> bool {
        matches!(
            code.unwrap_or(""),
            "ThrottlingException"
                | "Throttling"
                | "InternalFailure"
                | "InternalServerError"
                | "ServiceUnavailable"
                | "ServiceUnavailableException"
                | "RequestLimitExceeded"
        )
    }
    #[inline]
    fn to_smithy(dt: chrono::DateTime<Utc>) -> AwsDateTime {
        AwsDateTime::from_secs(dt.timestamp())
    }
    #[inline]
    fn parse_period_days(s: &str) -> Option<i64> {
        if let Some(stripped) = s.strip_prefix('P') {
            if let Some(days) = stripped.strip_suffix('D') {
                return days.parse::<i64>().ok();
            }
        }
        None
    }

    let (verb, params) = object
        .split_once(':')
        .map(|(v, rest)| (v.trim(), Some(rest.trim())))
        .unwrap_or((object.trim(), None));

    if !verb.eq_ignore_ascii_case("LookupEvents") {
        return Ok(0);
    }

    let mut start_dt: Option<AwsDateTime> = None;
    let mut end_dt: Option<AwsDateTime> = None;
    let mut want_root_identity = false;

    let mut req = client.lookup_events();
    if let Some(rest) = params {
        for pair in rest.split(';').map(|p| p.trim()).filter(|p| !p.is_empty()) {
            if let Some((k, v)) = pair.split_once('=') {
                match k.trim() {
                    "timeRange" => {
                        if let Some(days) = parse_period_days(v) {
                            let end = Utc::now();
                            let start = end - Duration::days(days);
                            start_dt = Some(to_smithy(start));
                            end_dt = Some(to_smithy(end));
                        }
                    }
                    "eventName" => {
                        let attr = LookupAttribute::builder()
                            .attribute_key(LookupAttributeKey::EventName)
                            .attribute_value(v.trim())
                            .build()?;
                        req = req.lookup_attributes(attr);
                    }
                    "username" | "userName" => {
                        let attr = LookupAttribute::builder()
                            .attribute_key(LookupAttributeKey::Username)
                            .attribute_value(v.trim())
                            .build()?;
                        req = req.lookup_attributes(attr);
                    }
                    "userIdentity.type" => {
                        if v.trim().eq_ignore_ascii_case("Root") {
                            want_root_identity = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(s) = start_dt {
        req = req.start_time(s);
    }
    if let Some(e) = end_dt {
        req = req.end_time(e);
    }

    let mut written: u64 = 0;
    let mut next_token: Option<String> = None;

    loop {
        let mut go = req.clone();
        if let Some(tok) = next_token.take() {
            go = go.next_token(tok);
        }

        // Send with retries for transient errors
        let mut attempt = 0u32;
        let resp = loop {
            match go.clone().send().await {
                Ok(r) => break r,
                Err(e) => {
                    let msg = e.to_string();
                    if looks_like_cred_or_perm(&msg) {
                        return Err(anyhow!(
                            "AWS permission/credential error in CloudTrail LookupEvents: {}",
                            msg
                        ));
                    }
                    if let SdkError::ServiceError(se) = &e {
                        let err = se.err();
                        let code = err.code().unwrap_or("UnknownServiceError");
                        let details = err.message().unwrap_or_default();
                        if is_transient_code(Some(code)) && attempt < 5 {
                            let delay_ms = 200u64 << attempt;
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            attempt += 1;
                            continue;
                        } else {
                            return Err(anyhow!(
                                "CloudTrail LookupEvents failed: code={code}, message={details}"
                            ));
                        }
                    } else {
                        if attempt < 5 {
                            let delay_ms = 200u64 << attempt;
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(anyhow!(
                            "CloudTrail LookupEvents failed (non-service): {}",
                            msg
                        ));
                    }
                }
            }
        };

        let slice: &[aws_sdk_cloudtrail::types::Event] = resp.events();
        for ev in slice.iter() {
            if let Some(raw) = ev.cloud_trail_event() {
                if want_root_identity {
                    if raw.contains("\"userIdentity\":{\"type\":\"Root\"")
                        || (raw.contains("\"userIdentity\":{") && raw.contains("\"type\":\"Root\""))
                    {
                        writeln!(out, "{}", raw)?;
                        written += raw.len() as u64 + 1;
                    }
                } else {
                    writeln!(out, "{}", raw)?;
                    written += raw.len() as u64 + 1;
                }
            }
        }
        if let Some(tok) = resp.next_token() {
            next_token = Some(tok.to_string());
        } else {
            break;
        }
    }

    Ok(written)
}

// ---------- AWS: CloudTrail S3 trail ingestion ----------
async fn collect_cloudtrail_s3_one(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    start_ms: i64,
    end_ms: i64,
    out: &mut File,
) -> Result<u64> {
    use flate2::read::GzDecoder;
    #[derive(serde::Deserialize)]
    struct CtFile {
        #[serde(default)]
        records: Vec<serde_json::Value>,
    }

    let obj = s3.get_object().bucket(bucket).key(key).send().await?;
    let body = obj.body.collect().await?.into_bytes().to_vec();

    // decode if gzip
    let is_gz = key.ends_with(".gz") || body.starts_with(&[0x1f, 0x8b]);
    let json_bytes = if is_gz {
        let mut dec = GzDecoder::new(&body[..]);
        let mut v = Vec::new();
        dec.read_to_end(&mut v)?;
        v
    } else {
        body
    };

    let parsed: CtFile = match serde_json::from_slice(&json_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let mut written = 0u64;
    for rec in parsed.records {
        let ok = rec
            .get("eventTime")
            .and_then(|v| v.as_str())
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok().map(|d| d.timestamp_millis()))
            .map(|t| t >= start_ms && t <= end_ms)
            .unwrap_or(true);
        if ok {
            let line = serde_json::to_vec(&rec)?;
            out.write_all(&line)?;
            out.write_all(b"\n")?;
            written += (line.len() + 1) as u64;
        }
    }
    Ok(written)
}

async fn collect_cloudtrail_s3(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    prefix: &str,
    start_ms: i64,
    end_ms: i64,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use aws_sdk_s3::types::Object;

    let mut tok: Option<String> = None;
    let mut total_written = 0u64;
    let mut out = File::create(out_path)?;

    loop {
        let mut req = s3.list_objects_v2().bucket(bucket).prefix(prefix);
        if let Some(t) = tok.take() {
            req = req.continuation_token(t);
        }
        let resp = req.send().await?;
        let objects: Vec<Object> = resp.contents.unwrap_or_default();

        for o in objects {
            let key = match o.key() {
                Some(k) => k,
                None => continue,
            };
            if !(key.ends_with(".json.gz") || key.ends_with(".json")) {
                continue;
            }
            total_written += collect_cloudtrail_s3_one(s3, bucket, key, start_ms, end_ms, &mut out).await?;
        }

        if let Some(nt) = resp.next_continuation_token {
            tok = Some(nt);
        } else {
            break;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws cloudtrail s3 collected ({} bytes)", total_written)),
    })
}

// ---------- AWS: GuardDuty findings ----------
async fn collect_guardduty(
    gd: &aws_sdk_guardduty::Client,
    time_start_ms: i64,
    time_end_ms: i64,
    severity_min: f64,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use aws_sdk_guardduty::types::{OrderBy, SortCriteria};
    use chrono::DateTime;
    use std::io::Write;

    // Pick first detector
    let dets = gd.list_detectors().send().await?;
    let detector = dets
        .detector_ids()
        .first()
        .ok_or_else(|| anyhow!("No GuardDuty detector found"))?
        .to_string();

    #[derive(serde::Serialize)]
    struct Row<'a> {
        id: Option<&'a str>,
        arn: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        created_at: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        updated_at: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        severity: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<&'a str>,
        #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
        ftype: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        account_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_instance_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_instance_type: Option<String>,
    }

    let mut tok: Option<String> = None;
    let mut out = File::create(out_path)?;
    let mut written_bytes = 0u64;

    loop {
        let mut list_req = gd
            .list_findings()
            .detector_id(&detector)
            .sort_criteria(
                SortCriteria::builder()
                    .attribute_name("updatedAt")
                    .order_by(OrderBy::Desc)
                    .build(),
            );
        if let Some(nt) = tok.take() {
            list_req = list_req.next_token(nt);
        }
        let lf = list_req.send().await?;
        let ids = lf.finding_ids().to_vec();
        if ids.is_empty() {
            break;
        }

        let get = gd
            .get_findings()
            .detector_id(&detector)
            .set_finding_ids(Some(ids))
            .send()
            .await?;

        for f in get.findings() {
            // time filter on updatedAt
            let updated_ms_ok = if let Some(ts) = f.updated_at() {
                match DateTime::parse_from_rfc3339(ts) {
                    Ok(dt) => {
                        let ms = dt.with_timezone(&chrono::Utc).timestamp_millis();
                        ms >= time_start_ms && ms <= time_end_ms
                    }
                    Err(_) => true,
                }
            } else {
                true
            };

            // severity filter
            let sev_ok = match f.severity() {
                Some(s) if severity_min > 0.0 => s >= severity_min,
                _ => true,
            };

            if updated_ms_ok && sev_ok {
                let (resource_instance_id, resource_instance_type) = f
                    .resource()
                    .and_then(|r| r.instance_details())
                    .map(|id| {
                        (
                            id.instance_id().map(|s| s.to_string()),
                            id.instance_type().map(|s| s.to_string()),
                        )
                    })
                    .unwrap_or((None, None));

                let row = Row {
                    id: f.id(),
                    arn: f.arn(),
                    created_at: f.created_at(),
                    updated_at: f.updated_at(),
                    severity: f.severity(),
                    title: f.title(),
                    ftype: f.r#type(),
                    description: f.description(),
                    account_id: f.account_id(),
                    resource_instance_id,
                    resource_instance_type,
                };
                let line = serde_json::to_vec(&row)?;
                out.write_all(&line)?;
                out.write_all(b"\n")?;
                written_bytes += (line.len() + 1) as u64;
            }
        }

        if let Some(next) = lf.next_token {
            tok = Some(next);
        } else {
            break;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws guardduty collected ({} bytes)", written_bytes)),
    })
}


// ---------- AWS: CloudWatch Logs (e.g., VPC Flow Logs) ----------
async fn collect_cloudwatch_logs(
    cwl: &aws_sdk_cloudwatchlogs::Client,
    group: &str,
    start_ms: i64,
    end_ms: i64,
    filter: Option<&str>,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    let mut tok: Option<String> = None;
    let mut out = File::create(out_path)?;
    let mut total = 0u64;

    loop {
        let mut req = cwl
            .filter_log_events()
            .log_group_name(group)
            .start_time(start_ms)
            .end_time(end_ms);
        if let Some(t) = tok.take() {
            req = req.next_token(t);
        }
        if let Some(f) = filter {
            req = req.filter_pattern(f);
        }
        let resp = req.send().await?;

        for ev in resp.events().iter() {
            #[derive(serde::Serialize)]
            struct Row<'a> {
                #[serde(skip_serializing_if = "Option::is_none")]
                id: Option<&'a str>,
                timestamp: i64,
                #[serde(skip_serializing_if = "Option::is_none")]
                ingestion_time: Option<i64>,
                message: &'a str,
                log_group: &'a str,
            }
            if let (Some(msg), Some(ts)) = (ev.message(), ev.timestamp()) {
                let row = Row {
                    id: ev.event_id(),
                    timestamp: ts,
                    ingestion_time: ev.ingestion_time(),
                    message: msg,
                    log_group: group,
                };
                let line = serde_json::to_vec(&row)?;
                out.write_all(&line)?;
                out.write_all(b"\n")?;
                total += (line.len() + 1) as u64;
            }
        }

        if let Some(nt) = resp.next_token {
            tok = Some(nt);
        } else {
            break;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws cloudwatch logs collected ({} bytes)", total)),
    })
}

// ---------- AWS: generic S3 logs under prefix (ALB/ELB/S3 access logs, etc.) ----------
async fn collect_s3_logs_prefix(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    prefix: &str,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use flate2::read::GzDecoder;

    let mut tok: Option<String> = None;
    let mut out = File::create(out_path)?;
    let mut count = 0u64;

    loop {
        let mut req = s3.list_objects_v2().bucket(bucket).prefix(prefix);
        if let Some(t) = tok.take() {
            req = req.continuation_token(t);
        }
        let resp = req.send().await?;
        for o in resp.contents.unwrap_or_default() {
            let key = match o.key() {
                Some(k) => k,
                None => continue,
            };
            let obj = s3.get_object().bucket(bucket).key(key).send().await?;
            let body = obj.body.collect().await?.into_bytes().to_vec();
            let is_gz = key.ends_with(".gz") || body.starts_with(&[0x1f, 0x8b]);

            if is_gz {
                let mut dec = GzDecoder::new(&body[..]);
                std::io::copy(&mut dec, &mut out)?;
            } else {
                out.write_all(&body)?;
            }
            out.write_all(b"\n")?; // delimiter between objects
            count += 1;
        }
        if let Some(nt) = resp.next_continuation_token {
            tok = Some(nt);
        } else {
            break;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws s3 logs collected (~{} objects)", count)),
    })
}

// ---------- AWS: SecurityHub findings ----------
async fn collect_securityhub_findings(
    sh: &aws_sdk_securityhub::Client,
    time_start_ms: i64,
    time_end_ms: i64,
    severity_min: f64,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use aws_sdk_securityhub::types::{AwsSecurityFindingFilters, StringFilter};
    use chrono::DateTime;
    use std::io::Write;

    let _start_iso = DateTime::from_timestamp_millis(time_start_ms)
        .unwrap()
        .to_rfc3339();
    let _end_iso = DateTime::from_timestamp_millis(time_end_ms)
        .unwrap()
        .to_rfc3339();

    #[derive(serde::Serialize)]
    struct FindingRow<'a> {
        id: Option<&'a str>,
        arn: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        created_at: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        updated_at: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        severity: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        product_arn: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        product_name: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        company_name: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        region: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        generator_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aws_account_id: Option<&'a str>,
    }

    let mut tok: Option<String> = None;
    let mut out = File::create(out_path)?;
    let mut written_bytes = 0u64;

    loop {
        let mut req = sh.get_findings();

        if let Some(nt) = tok.take() {
            req = req.next_token(nt);
        }

        // Apply severity filter if specified
        if severity_min > 0.0 {
            let severity_label = match severity_min {
                s if s >= 8.0 => "CRITICAL",
                s if s >= 6.0 => "HIGH",
                s if s >= 4.0 => "MEDIUM",
                s if s >= 2.0 => "LOW",
                _ => "INFORMATIONAL",
            };
            req = req.filters(
                AwsSecurityFindingFilters::builder()
                    .severity_label(
                        StringFilter::builder()
                            .value(severity_label)
                            .build(),
                    )
                    .build(),
            );
        }

        let resp = req.send().await?;

        for f in resp.findings() {
            let row = FindingRow {
                id: f.id(),
                arn: f.id(), // Use id as arn since arn() method doesn't exist
                created_at: f.created_at(),
                updated_at: f.updated_at(),
                severity: f.severity().and_then(|s| s.label().map(|l| l.as_str())),
                title: f.title(),
                description: f.description(),
                product_arn: f.product_arn(),
                product_name: f.product_name(),
                company_name: f.company_name(),
                region: f.region(),
                generator_id: f.generator_id(),
                aws_account_id: f.aws_account_id(),
            };
            let line = serde_json::to_vec(&row)?;
            out.write_all(&line)?;
            out.write_all(b"\n")?;
            written_bytes += (line.len() + 1) as u64;
        }

        if let Some(next) = resp.next_token {
            tok = Some(next);
        } else {
            break;
        }
    }

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws securityhub collected ({} bytes)", written_bytes)),
    })
}

// ---------- AWS: IAM Access Analyzer findings ----------
async fn collect_iam_access_analyzer(
    _aa: &aws_sdk_accessanalyzer::Client,
    _time_start_ms: i64,
    _time_end_ms: i64,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use std::io::Write;

    let mut out = File::create(out_path)?;
    let mut written_bytes = 0u64;

    // Simplified implementation - just write a placeholder for now
    let placeholder = serde_json::json!({
        "note": "IAM Access Analyzer collection not fully implemented yet",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    let line = serde_json::to_vec(&placeholder)?;
    out.write_all(&line)?;
    out.write_all(b"\n")?;
    written_bytes += (line.len() + 1) as u64;

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws iam access analyzer placeholder ({} bytes)", written_bytes)),
    })
}

// ---------- AWS: Config rules and compliance ----------
async fn collect_config_rules(
    _config: &aws_sdk_config::Client,
    _time_start_ms: i64,
    _time_end_ms: i64,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use std::io::Write;

    let mut out = File::create(out_path)?;
    let mut written_bytes = 0u64;

    // Simplified implementation - just write a placeholder for now
    let placeholder = serde_json::json!({
        "note": "Config rules collection not fully implemented yet",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    let line = serde_json::to_vec(&placeholder)?;
    out.write_all(&line)?;
    out.write_all(b"\n")?;
    written_bytes += (line.len() + 1) as u64;

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws config rules placeholder ({} bytes)", written_bytes)),
    })
}

// ---------- AWS: Inspector2 findings ----------
async fn collect_inspector2_findings(
    _inspector: &aws_sdk_inspector2::Client,
    _time_start_ms: i64,
    _time_end_ms: i64,
    out_path: &Path,
) -> Result<ArtifactMeta> {
    use std::io::Write;

    let mut out = File::create(out_path)?;
    let mut written_bytes = 0u64;

    // Simplified implementation - just write a placeholder for now
    let placeholder = serde_json::json!({
        "note": "Inspector2 findings collection not fully implemented yet",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    let line = serde_json::to_vec(&placeholder)?;
    out.write_all(&line)?;
    out.write_all(b"\n")?;
    written_bytes += (line.len() + 1) as u64;

    let meta = fs::metadata(out_path)?;
    Ok(ArtifactMeta {
        path: out_path.to_string_lossy().to_string(),
        bytes: meta.len() as u64,
        sha256: String::new(),
        notes: Some(format!("aws inspector2 placeholder ({} bytes)", written_bytes)),
    })
}

// ---------- AWS dispatcher ----------
pub async fn collect_entries(
    section: &SectionConfig,
    output_dir: &str,
    merged_credentials: &IndexMap<String, String>,
) -> Result<Vec<ArtifactMeta>> {
    use aws_config::meta::region::RegionProviderChain;
    use aws_config::{BehaviorVersion, Region};
    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_credential_types::Credentials;
    use aws_sdk_cloudtrail as cloudtrail;

    fs::create_dir_all(output_dir)?;
    let out_dir = Path::new(output_dir);

    let mut results: Vec<ArtifactMeta> = Vec::new();
    let entries = match &section.entries {
        Some(e) => e,
        None => return Ok(results),
    };

    let access_key = merged_credentials
        .get("AWS_ACCESS_KEY_ID")
        .ok_or_else(|| anyhow!("AWS_ACCESS_KEY_ID missing"))?;
    let secret = merged_credentials
        .get("AWS_SECRET_ACCESS_KEY")
        .ok_or_else(|| anyhow!("AWS_SECRET_ACCESS_KEY missing"))?;
    let region = merged_credentials
        .get("AWS_REGION")
        .cloned()
        .unwrap_or_else(|| "us-east-1".to_string());
    let session = merged_credentials.get("AWS_SESSION_TOKEN").cloned();

    let creds = Credentials::new(access_key, secret, session, None, "aralez_static");
    let rp = RegionProviderChain::first_try(Region::new(region));
    let conf = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(SharedCredentialsProvider::new(creds))
        .region(rp)
        .load()
        .await;

    let ct_client = cloudtrail::Client::new(&conf);
    let s3 = aws_sdk_s3::Client::new(&conf);
    let cwl = aws_sdk_cloudwatchlogs::Client::new(&conf);
    let gd = aws_sdk_guardduty::Client::new(&conf);
    let sh = aws_sdk_securityhub::Client::new(&conf);
    let aa = aws_sdk_accessanalyzer::Client::new(&conf);
    let config_client = aws_sdk_config::Client::new(&conf);
    let inspector = aws_sdk_inspector2::Client::new(&conf);

    for (group, vec_cfg) in entries.iter() {
        for (idx, sc) in vec_cfg.iter().enumerate() {
            let out_path = resolve_output_path(out_dir, group, idx, sc);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut notes: Vec<String> = vec![];
            let mut total_bytes: u64 = 0;

            let objs = sc.objects.clone().unwrap_or_default();
            // For LookupEvents we append to the same file if multiple lookups are listed.
            let mut out_for_lookup = File::options()
                .append(true)
                .create(true)
                .open(&out_path)
                .with_context(|| format!("Cannot create output file {:?}", out_path))?;

            for o in objs {
                let (verb, params) = o
                    .split_once(':')
                    .map(|(v, r)| (v.trim(), Some(r.trim())))
                    .unwrap_or((o.trim(), None));

                // Common knobs
                let mut time_range: Option<String> = None;
                let mut since: Option<String> = None;
                let mut until: Option<String> = None;

                // AWS-specific knobs
                let mut bucket = String::new();
                let mut prefix = String::new();
                let mut group_name = String::new();
                let mut filter: Option<String> = None;
                let mut severity_min: f64 = 0.0;

                if let Some(rest) = params {
                    for pair in rest.split(';').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                        if let Some((k, v)) = pair.split_once('=') {
                            match k.trim() {
                                "timeRange" => time_range = Some(v.trim().to_string()),
                                "since" => since = Some(v.trim().to_string()),
                                "until" => until = Some(v.trim().to_string()),
                                "bucket" => bucket = v.trim().to_string(),
                                "prefix" => prefix = v.trim().to_string(),
                                "group" | "logGroup" => group_name = v.trim().to_string(),
                                "filter" => filter = Some(v.trim().to_string()),
                                "severityMin" => {
                                    severity_min = v.trim().parse().unwrap_or(0.0)
                                }
                                _ => {}
                            }
                        }
                    }
                }
                let (start_ms, end_ms) =
                    window_ms(since.as_deref(), until.as_deref(), time_range.as_deref())?;

                match verb.to_ascii_lowercase().as_str() {
                    "lookupevents" => {
                        let bytes = write_lookup_events_jsonl(&ct_client, &o, &mut out_for_lookup).await?;
                        total_bytes += bytes;
                        notes.push(format!("cloudtrail history (+{} bytes)", bytes));
                    }
                    "cloudtrails3" => {
                        let meta = collect_cloudtrail_s3(
                            &s3,
                            &bucket,
                            &prefix,
                            start_ms,
                            end_ms,
                            &out_path,
                        )
                        .await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "guarddutyfindings" => {
                        let meta =
                            collect_guardduty(&gd, start_ms, end_ms, severity_min, &out_path)
                                .await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "securityhubfindings" => {
                        let meta = collect_securityhub_findings(&sh, start_ms, end_ms, severity_min, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "iamaccessanalyzer" => {
                        let meta = collect_iam_access_analyzer(&aa, start_ms, end_ms, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "configrules" => {
                        let meta = collect_config_rules(&config_client, start_ms, end_ms, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "inspector2findings" => {
                        let meta = collect_inspector2_findings(&inspector, start_ms, end_ms, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    "cloudwatchlogs" => {
                        let grp = if !group_name.is_empty() {
                            group_name.clone()
                        } else {
                            // allow "CloudWatchLogs:group=/aws/..." not provided -> treat verb param as group
                            group_name.clone()
                        };
                        if grp.is_empty() {
                            notes.push("cloudwatch logs skipped (no group=...)".into());
                        } else {
                            let meta = collect_cloudwatch_logs(
                                &cwl,
                                &grp,
                                start_ms,
                                end_ms,
                                filter.as_deref(),
                                &out_path,
                            )
                            .await?;
                            total_bytes += meta.bytes;
                            notes.push(meta.notes.unwrap_or_default());
                        }
                    }
                    "s3logs" => {
                        let meta = collect_s3_logs_prefix(&s3, &bucket, &prefix, &out_path).await?;
                        total_bytes += meta.bytes;
                        notes.push(meta.notes.unwrap_or_default());
                    }
                    _ => {
                        // unknown object for AWS – ignore silently to keep config portable
                    }
                }
            }

            results.push(ArtifactMeta {
                path: out_path.to_string_lossy().to_string(),
                bytes: total_bytes as u64,
                sha256: String::new(),
                notes: Some(format!("aws: {}", notes.join(" | "))),
            });
        }
    }

    Ok(results)
}
