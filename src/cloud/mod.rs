//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Aralez. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//

pub mod common;
pub mod aws;
pub mod azure;
pub mod gcp;

pub use common::ArtifactMeta;

use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;

use crate::config::SectionConfig;

/// Entry called by main.rs
pub async fn collect_section(
    section_name: &str,
    section: &SectionConfig,
    output_dir: &str,
    merged_credentials: &IndexMap<String, String>,
) -> Result<Vec<ArtifactMeta>> {
    let provider = common::detect_provider(merged_credentials)
        .ok_or_else(|| anyhow!("Missing or invalid credentials for section '{}'", section_name))?;

    // Fail fast if creds are wrong
    common::preflight(provider, merged_credentials)
        .await
        .with_context(|| format!("Credential preflight failed for provider '{}'", provider))?;

    // Dispatch to provider-specific collectors
    match provider {
        "aws" => aws::collect_entries(section, output_dir, merged_credentials).await,
        "azure" => azure::collect_entries(section, output_dir, merged_credentials).await,
        "gcp" => gcp::collect_entries(section, output_dir, merged_credentials).await,
        _ => Err(anyhow!(
            "Provider '{}' not supported in this build of collect_section",
            provider
        )),
    }
}
