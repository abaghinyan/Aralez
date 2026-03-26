<div align="center">
  <img src="./assets/logo.png" alt="Aralez Logo" width="280" />

  <h1>Aralez</h1>
  <strong>Next-Generation Cross-Platform Forensic Triage & Extraction</strong>

  <p>
    <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge&logo=apache" alt="License"></a>
    <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge&logo=linux" alt="Platform">
    <img src="https://img.shields.io/badge/Rust-🦀-orange?style=for-the-badge&logo=rust" alt="Rust">
    <img src="https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge" alt="Build">
  </p>

  <p>
    <em>Fast. Invisible. Crash-Resilient. Built for Enterprise Incident Response.</em>
  </p>
</div>

---

**Aralez** is a high-performance cross-platform forensic triage tool engineered in **Rust**. It automates the secure, reliable collection of critical system data (MFT, Registry, Logs, active connections) to accelerate incident response workflows, hunting, and root-cause analysis at an enterprise scale.

> ⚡ **Quick Start**
> - **Windows:** `aralez_x64_windows.exe` (run as Administrator)
> - **Linux:** `aralez_x64_linux` (run as Root)

---

## ✨ Why Aralez?

Aralez is designed for scale and stealth, solving the hardest problems in modern digital forensics:

* 🌪️ **Zero-Folder Streaming Compression:** Collect artifacts directly into AES-256 encrypted `.zip` or crash-proof `.tar.zst` streams on the fly. Bypasses intermediate disk storage entirely, cutting disk footprint by 50%.
* 🏢 **Enterprise Mass-Deployment:** Native support for execution via BITS, SCCM, GPO, SSH, Ansible, and Puppet. Push to 10,000 endpoints in minutes.
* 🥷 **Silent & Interruption-Safe:** Run completely hidden (`--silent`). Graceful `Ctrl+C` handling guarantees that if you abort midway, the archive flawlessly finalizes with every artifact collected up to that millisecond.
* ☁️ **Cloud-Native Uploads:** Ship evidence instantly to AWS S3, MinIO, SFTP, or SMB shares straight from the endpoint memory.

---

## 🚀 Getting Started

Download the latest precompiled binaries from the **Releases** page or clone the repository to build from source. 

### Basic Usage

```bash
# General full collection (Windows & Linux)
sudo ./aralez

# 🌪️ Stream directly to a compressed ZIP (No artifacts touch disk!)
sudo ./aralez --stream

# 🌪️ Stream to a crash-proof TAR (Zstandard compression)
sudo ./aralez --stream --compression tar

# 🥷 Execute silently (No terminal output, ideal for SCCM/GPO)
sudo ./aralez --stream --silent
```

---

## 📤 Output & Cloud Export

Aralez seamlessly integrates with your forensic pipeline. Use the `-o` (`--output`) flag to route evidence directly to your collection servers. Local archives are automatically zeroed-out after a successful remote transfer.

```bash
# Upload results to an SFTP server
sudo ./aralez -o sftp://forensic@collector.corp/incoming

# Upload to an AWS S3 Bucket
sudo ./aralez -o s3://forensic-bucket/evidence/

# Upload to a Custom MinIO S3 instance
sudo ./aralez -o s3://my-minio-server:9000/bucket \
    --s3-endpoint "https://my-minio-server:9000" \
    --s3-access-key "KEY" --s3-secret-key "SECRET"

# Pipe directly to an internal SMB Share (Windows)
aralez.exe -o smb://fileserver/forensics/incoming
```

---

## ⚙️ CLI Reference

Aralez is heavily configurable via the command line or via its embedded `config.yml`.

| Flag / Option | Description |
|---------------|-------------|
| `--stream` | Enable **Zero-Folder Streaming**. Archives artifacts in memory directly to disk. |
| `--compression <FMT>`| Engine to use: `zip` (default, AES-256) or `tar` (crash-resilient `.tar.zst`). |
| `--silent` | Suppress all stdout/stderr output (logs are still saved inside the archive). |
| `-o, --output <URI>` | Push the final collection zip to `sftp://`, `s3://`, `smb://`, or local `/path`. |
| `-e, --encrypt <PW>` | Encrypt the output archive with the provided password. |
| `-d, --default_drive`| Default drive letter to process (Windows only, default: `C`). |
| `-w, --workdir <DIR>`| Work directory for legacy (non-stream) collection. |

---

## 🏗️ Enterprise Automation

Aralez provides battle-tested deployment scripts inside the `deploy/` folder for immediate integration into your IT infrastructure:

### Windows
*   📄 **`Deploy-AralezBits.ps1`**: Rapidly pull the binary via BITS and execute silently.
*   📄 **`Deploy-AralezGpo.bat`**: Universal GPO Startup Script wrapper.
*   📄 **`Install-AralezSccm.ps1`**: Tuned specifically for SCCM/Intune packaging.

### Linux
*   📄 **`deploy_linux.sh`**: Wrap with `xargs` to deploy across fleets via SSH.
*   📄 **`deploy_aralez.yml`**: Official Ansible playbook.

> 📚 See [**`deploy/DEPLOYMENT.md`**](deploy/DEPLOYMENT.md) for step-by-step enterprise guides.

---

## 📖 Documentation

Comprehensive documentation - including deployment guides, configuration references, and parser details - is available on the [official website](https://aralez.co).

---

## 🧱 Building from Source

Aralez utilizes Cargo features to keep the core binary extremely lightweight, while allowing you to compile in heavy capabilities (like AWS SDKs) only when needed.

```bash
# 1. Compile the minimal core binary
cargo build --release

# 2. Compile with Cloud S3 Upload support
cargo build --release --features upload-s3

# 3. Everything enabled (Extended Tools + SMB + SFTP + S3)
cargo build --release --features "extended-tools,upload"
```

> **Note**: Building the `upload-s3` feature requires **rustc ≥ 1.91.1**. Update via `rustup update stable`.

---

## 🤝 Contributing & Support

We welcome pull requests representing new parsers, hunting rules, and performance tweaks to make **Aralez** the ultimate responder's asset. 
* Please submit PRs with descriptive explanations of the performance impacts.
* Open an **Issue** to report bugs or suggest enhancements.

### License

**Aralez** is licensed under the [Apache-2.0 License](LICENSE).
