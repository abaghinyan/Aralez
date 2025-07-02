// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan

use std::fs;
use std::io::Write;
use std::path::Path;

pub fn run(output_path: &Path) {
    let mut output = match fs::File::create(output_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] Cannot create output file {}: {}", output_path.display(), e);
            return;
        }
    };

    writeln!(output, "=== Package Manager Audit ===\n").unwrap();

    audit_apt_packages(&mut output);
    audit_rpm_packages(&mut output);
    collect_apt_sources(&mut output);
    collect_yum_repos(&mut output);
}

fn audit_apt_packages<W: Write>(output: &mut W) {
    let dpkg_status_path = "/var/lib/dpkg/status";
    writeln!(output, "[APT Packages] from {}", dpkg_status_path).unwrap();

    if let Ok(contents) = fs::read_to_string(dpkg_status_path) {
        for section in contents.split("\n\n") {
            let mut name = None;
            let mut version = None;

            for line in section.lines() {
                if let Some(pkg) = line.strip_prefix("Package: ") {
                    name = Some(pkg.to_string());
                } else if let Some(ver) = line.strip_prefix("Version: ") {
                    version = Some(ver.to_string());
                }
            }

            if let Some(pkg) = name {
                if let Some(ver) = version {
                    writeln!(output, "{} ({})", pkg, ver).unwrap();
                } else {
                    writeln!(output, "{}", pkg).unwrap();
                }
            }
        }
    } else {
        writeln!(output, "[WARN] Could not read {}", dpkg_status_path).unwrap();
    }
}

fn audit_rpm_packages<W: Write>(output: &mut W) {
    writeln!(output, "\n[RPM Packages] from /var/lib/rpm/").unwrap();
    let rpm_dir = "/var/lib/rpm/Packages";
    if Path::new(rpm_dir).exists() {
        writeln!(output, "[INFO] RPM database found (parsing not implemented without external crate)").unwrap();
    } else {
        writeln!(output, "[INFO] RPM database not found").unwrap();
    }
}

fn collect_apt_sources<W: Write>(output: &mut W) {
    writeln!(output, "\n[APT Sources] from /etc/apt/sources.list and /etc/apt/sources.list.d/").unwrap();
    let paths = ["/etc/apt/sources.list", "/etc/apt/sources.list.d"];

    for path in &paths {
        let path = Path::new(path);
        if path.is_file() {
            if let Ok(content) = fs::read_to_string(path) {
                writeln!(output, "- {}:", path.display()).unwrap();
                for line in content.lines() {
                    writeln!(output, "  {}", line).unwrap();
                }
            }
        } else if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let sub = entry.path();
                    if let Ok(content) = fs::read_to_string(&sub) {
                        writeln!(output, "- {}:", sub.display()).unwrap();
                        for line in content.lines() {
                            writeln!(output, "  {}", line).unwrap();
                        }
                    }
                }
            }
        }
    }
}

fn collect_yum_repos<W: Write>(output: &mut W) {
    writeln!(output, "\n[YUM Repositories] from /etc/yum.repos.d/").unwrap();
    let path = Path::new("/etc/yum.repos.d");
    if path.exists() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let fpath = entry.path();
                if let Ok(content) = fs::read_to_string(&fpath) {
                    writeln!(output, "- {}:", fpath.display()).unwrap();
                    for line in content.lines() {
                        writeln!(output, "  {}", line).unwrap();
                    }
                }
            }
        }
    }
}
