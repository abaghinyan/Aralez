<p align="center">
  <img src="./assets/logo.png" alt="Aralez Logo" width="274" height="256"/>
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![](https://img.shields.io/badge/build-passing-brightgreen)

# Aralez

**Aralez is a powerful cross-platform forensic triage tool for Windows and Linux.**
It automates the secure collection of critical system data, enabling investigators and responders to accelerate incident response, streamline forensic workflows, and maintain data integrity at scale.

> ⚡ **Note**:
>
> * On **Windows**, use `aralez_x64_windows.exe` or `aralez_x86_windows.exe` (requires administrative privileges).
> * On **Linux**, use `aralez_x64_linux` or `aralez_x86_linux` binary (requires root privileges).

---

## ✨ Features at a Glance

* 🔍 **Cross-Platform Support** - Collect forensic data on both Windows and Linux systems.
* ⚡ **Automated Data Collection** - Extracts information from NTFS/ext file systems, system logs, and critical artifacts.
* 🛠️ **Integrated Tool Support** - Leverages internal, external, and system tools for comprehensive analysis.
* 🔐 **Secure by Design** - Uses AES-GCM encryption to protect sensitive data from accidental propagation.
* ⚙️ **Customizable Configurations** - Update the embedded YAML configuration directly or via a new binary.
* 📤 **Flexible Output Destinations** - Upload results to S3, SFTP, SMB shares, or local/network folders.
* 🚀 **Enterprise-Scale Deployment** - Deploy and collect at scale via SSH, WinRM, Ansible, SCCM, GPO, BITS, or Puppet.

---

## 🚀 Quick Start

1. **Download**
   Clone the repository or grab a precompiled binary:

   * **Windows (64-bit):** `aralez_x64_windows.exe`
   * **Windows (32-bit):** `aralez_x86_windows.exe`
   * **Linux (64-bit):** `aralez_x64_linux`
   * **Linux (32-bit):** `aralez_x86_linux`

2. **Execute**

   * On Windows: Run the appropriate `.exe` as **Administrator**
   * On Linux: Run:

     ```bash
     sudo ./aralez
     ```

3. **Review Outputs**
   Collected data and logs are saved in a structured format, ready for forensic analysis.

---

## ⚙️ CLI Options

| Flag | Long | Description |
|------|------|-------------|
| `-o` | `--output` | Upload/copy the result zip to a destination |
| `-w` | `--workdir` | Working directory for temporary artifact collection |
| `-e` | `--encrypt` | Encrypt the output zip with a password |
| `-d` | `--default_drive` | Default drive to process (Windows only, default: `C`) |
| | `--debug` | Enable verbose debug logging |
| | `--show-config` | Display the embedded configuration |
| | `--check-config` | Validate the embedded configuration |

### Examples

```bash
# Basic collection
sudo ./aralez

# Upload results to SFTP
sudo ./aralez -o sftp://forensic@collector.corp/incoming

# Upload to S3
sudo ./aralez -o s3://forensic-bucket/incoming

# Upload to SMB share
aralez.exe -o smb://fileserver/forensics/incoming

# Copy to a local/network folder
sudo ./aralez -o /mnt/nfs/triage

# Use a custom working directory
sudo ./aralez -w /tmp/aralez_work -o sftp://user@host/triage

# Encrypt output with a password
sudo ./aralez -e MySecurePassword123
```

> 📝 **Note:** When `--output` is used with a remote destination (S3, SFTP, SMB), the local zip file is automatically removed after a successful upload. If the destination is a local folder, the zip is moved there.

---

## 📤 Upload Destinations

Aralez can upload the triage zip directly to a remote destination via the `--output` / `-o` flag or via the `output:` section in `config.yml`.

| Destination | CLI Format | Feature Flag Required |
|-------------|------------|----------------------|
| **Local/Network folder** | `/path/to/folder` or `\\server\share` | None |
| **SMB** | `smb://server/share/path` | None |
| **SFTP** | `sftp://user@host:port/path` | `upload-sftp` |
| **S3** | `s3://bucket/prefix` | `upload-s3` |

### S3 Credential Management

When uploading to S3, credentials are resolved in this order:

1. **Environment variables** — `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
2. **Shared credentials file** — `~/.aws/credentials` (via `aws configure`)
3. **IAM Instance Profile** — Automatic on EC2/ECS (recommended for cloud deployments)

> ⚠️ **Do not** put credentials in `config.yml` since it is embedded in the binary.

---

## 📖 Documentation

Comprehensive documentation - including configuration guides, usage examples, and tool descriptions - is available on the [official website](https://aralez.co).

---

## 🧱 Building from Source

Aralez uses Cargo features to control optional capabilities.

| Feature | Description |
|---------|-------------|
| `extended-tools` | Bundles extra executables (e.g., WinPmem for memory dump) |
| `memdump` | Alias for `extended-tools` |
| `upload-s3` | Enables S3 upload support |
| `upload-sftp` | Enables SFTP upload support |
| `upload-smb` | Enables SMB upload support |
| `upload` | Enables all upload backends (S3 + SFTP + SMB) |

```bash
# Default (minimal binary)
cargo build --release

# With all upload backends
cargo build --release --features upload

# With specific upload backend only
cargo build --release --features upload-s3

# With extended tools + all uploads
cargo build --release --features "extended-tools,upload"

# Cross-compile for Windows
cargo build --release --target x86_64-pc-windows-gnu --features upload
```

> 📝 If you use `--output` with a destination whose feature flag is not enabled, Aralez will print an error indicating which feature to enable.

> ⚠️ **Rust version requirement:** The `upload-s3` (and `upload`) feature requires **rustc ≥ 1.91.1** due to the AWS SDK dependency. Run `rustup update stable` to upgrade.

---

## 🏢 Enterprise Deployment

Aralez includes ready-to-use deployment scripts for mass collection across large environments.

| Method | OS | Script |
|--------|-----|--------|
| SSH + xargs | Linux | `deploy/deploy_linux.sh` |
| WinRM / PsExec | Windows | `deploy/Deploy-Aralez.ps1` |
| Ansible | Both | `deploy/deploy_aralez.yml` |
| SCCM / Intune | Windows | `deploy/Install-AralezSccm.ps1` |
| GPO (Startup) | Windows | `deploy/Deploy-AralezGpo.bat` |
| BITS | Windows | `deploy/Deploy-AralezBits.ps1` |
| Puppet | Both | `deploy/aralez_puppet.pp` |

```bash
# Deploy to Linux machines via SSH
./deploy/deploy_linux.sh -t targets.txt -b ./aralez_x64_linux -j 100

# Deploy to Windows machines via Ansible
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml \
    -e "output=sftp://forensic@collector.corp/incoming"
```

See [`deploy/DEPLOYMENT.md`](deploy/DEPLOYMENT.md) for full documentation.

---

## 🤝 Contributing

We welcome contributions to **Aralez**!

* Submit pull requests with clear descriptions of your changes.
* Open issues to report bugs or suggest improvements.

Your contributions help make Aralez better for the entire incident response community.

---

## 📜 License

Aralez is open-source software licensed under the **Apache-2.0 License**.
See the [LICENSE](LICENSE) file for details.
