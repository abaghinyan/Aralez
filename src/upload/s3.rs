// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

use aws_config;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use std::path::Path;

/// Upload the zip file to an S3 bucket.
///
/// If `access_key` and `secret_key` are provided, uses explicit credentials.
/// Otherwise, uses the default AWS credential chain (env vars, instance profile, etc.).
/// If `endpoint` is provided, uses a custom S3-compatible endpoint (e.g. MinIO).
pub fn upload(
    zip_path: &str,
    bucket: &str,
    prefix: Option<&str>,
    region: Option<&str>,
    endpoint: Option<&str>,
    access_key: Option<&str>,
    secret_key: Option<&str>,
) -> Result<(), anyhow::Error> {
    // Run the async upload in a blocking context
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create tokio runtime: {}", e))?;

    rt.block_on(async {
        upload_async(zip_path, bucket, prefix, region, endpoint, access_key, secret_key).await
    })
}

async fn upload_async(
    zip_path: &str,
    bucket: &str,
    prefix: Option<&str>,
    region: Option<&str>,
    endpoint: Option<&str>,
    access_key: Option<&str>,
    secret_key: Option<&str>,
) -> Result<(), anyhow::Error> {
    let zip_file = Path::new(zip_path);
    let file_name = zip_file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid zip file path"))?
        .to_string_lossy();

    let key = match prefix {
        Some(p) => {
            let p = p.trim_end_matches('/');
            format!("{}/{}", p, file_name)
        }
        None => file_name.to_string(),
    };

    dprintln!("[INFO] Uploading to S3: s3://{}/{}", bucket, key);

    // Build AWS config
    let mut config_loader = aws_config::from_env();

    if let Some(r) = region {
        config_loader = config_loader.region(aws_config::Region::new(r.to_string()));
    }

    if let (Some(ak), Some(sk)) = (access_key, secret_key) {
        let creds = aws_sdk_s3::config::Credentials::new(
            ak, sk, None, None, "aralez-config",
        );
        config_loader = config_loader.credentials_provider(creds);
    }

    let config = config_loader.load().await;

    // Build S3 client, optionally with custom endpoint (MinIO, etc.)
    let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&config);
    if let Some(ep) = endpoint {
        s3_config_builder = s3_config_builder
            .endpoint_url(ep)
            .force_path_style(true);
        dprintln!("[INFO] Using custom S3 endpoint: {}", ep);
    }
    let client = Client::from_conf(s3_config_builder.build());

    let body = ByteStream::from_path(zip_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read zip file for S3 upload: {}", e))?;

    client
        .put_object()
        .bucket(bucket)
        .key(&key)
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("S3 upload failed: {}", e))?;

    println!("[INFO] Zip file uploaded to s3://{}/{}", bucket, key);
    dprintln!("[INFO] Zip file uploaded to s3://{}/{}", bucket, key);

    Ok(())
}
