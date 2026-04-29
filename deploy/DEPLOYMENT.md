# Aralez Enterprise Deployment Guide

Deploy and execute Aralez at scale across Windows and Linux environments.

> [!NOTE]
> Aralez builds embed the `config.yml` directly into the binary at compile time. You only need to distribute the **single executable** to target machines — no config files, no dependencies.

---

## Table of Contents

1. [Deployment Methods](#deployment-methods-at-a-glance)
2. [Linux — Bash + SSH](#1-linux--bash--ssh)
3. [Windows — PowerShell + WinRM](#2-windows--powershell--winrm)
4. [Ansible (Cross-Platform)](#3-ansible-cross-platform)
5. [SCCM / Intune](#4-sccm--intune)
6. [Group Policy (GPO)](#5-group-policy-gpo---zero-touch)
7. [BITS Transfer](#6-windows-bits-transfer)
8. [Puppet](#7-puppet)
9. [Working Directory (-w)](#8-working-directory---w)
10. [Upload Destinations (-o)](#9-upload-destinations---o)
11. [S3 / MinIO Configuration](#10-s3--minio-configuration)
12. [Result Collection Strategies](#11-result-collection-strategies)
13. [Architecture Decision Guide](#12-architecture-decision-guide)
14. [Security Considerations](#13-security-considerations)
15. [Performance Benchmarks](#14-performance-benchmarks)
16. [Troubleshooting](#15-troubleshooting)

---

## Deployment Methods at a Glance

| Method | OS | Dependencies | Best For | Scale |
|--------|-----|-------------|----------|-------|
| **Bash + SSH** | Linux | SSH keys | Simple, no extra tools | Any |
| **PowerShell + WinRM** | Windows | WinRM enabled | Domain environments | Any |
| **PowerShell + PsExec** | Windows | Sysinternals PsExec | Non-WinRM environments | Any |
| **Ansible** | Both | Ansible installed | Existing Ansible infrastructure | Any |
| **SCCM / Intune** | Windows | SCCM/Intune Agent | Enterprise centralized deployment | Any |
| **GPO (Zero-Touch)** | Windows | Active Directory | Silent deployment at boot | Any |
| **BITS** | Windows | BITS Service | Slow/constrained network links | Any |
| **Puppet** | Both | Puppet Agent | Infrastructure-as-code management | Any |

---

## 1. Linux — Bash + SSH

### Prerequisites
- SSH key-based auth configured (`ssh-copy-id root@host`)
- Aralez binary (`aralez_x64_linux` or `aralez_x86_linux`)

### Quick Start

```bash
# Prepare targets file (one host per line)
cat > targets_linux.txt <<EOF
10.0.1.1
10.0.1.2
10.0.1.3
web-server-01.internal.corp
db-server-02.internal.corp
EOF

# Deploy to all targets (50 parallel by default)
./deploy/deploy_linux.sh -t targets_linux.txt -b ./aralez_x64_linux

# Deploy with SFTP result upload
./deploy/deploy_linux.sh \
    -t targets_linux.txt \
    -b ./aralez_x64_linux \
    -a "--output sftp://forensic@collector.corp/incoming"

# Deploy with custom working directory + upload
./deploy/deploy_linux.sh \
    -t targets_linux.txt \
    -b ./aralez_x64_linux \
    -a "--workdir /tmp/aralez_work --output sftp://forensic@collector.corp/incoming"

# Dry run — see what would happen without executing
./deploy/deploy_linux.sh -t targets_linux.txt -b ./aralez_x64_linux -n
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Targets file (required) | — |
| `-b` | Aralez binary (required) | — |
| `-u` | SSH user | `root` |
| `-k` | SSH key file | default |
| `-p` | SSH port | `22` |
| `-j` | Parallel jobs | `50` |
| `-o` | Remote `--output` destination | — |
| `-C` | Local dir to collect `.zip` results | — |
| `-a` | Extra aralez arguments | — |
| `-n` | Dry run | — |

### Scaling Tips

**SSH multiplexing** (reuses connections, dramatically faster):
```
# ~/.ssh/config
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
```

Create the sockets directory:
```bash
mkdir -p ~/.ssh/sockets
```

**Parallelism tuning:**
```bash
# Small  → -j 50  (safe default)
# Medium → -j 100
# Large  → -j 200
# Massive → -j 500 (check ulimit -n first)
```

**Pre-validate connectivity before deploying:**
```bash
while IFS= read -r host; do
    ssh -o ConnectTimeout=3 -o BatchMode=yes root@"$host" "echo OK" 2>/dev/null \
        && echo "[OK] $host" \
        || echo "[FAIL] $host"
done < targets_linux.txt
```

**Segment targets by site/subnet for phased rollout:**
```bash
# Phase 1: Critical servers
./deploy/deploy_linux.sh -t targets_critical.txt -b ./aralez_x64_linux -j 10

# Phase 2: Standard workstations
./deploy/deploy_linux.sh -t targets_workstations.txt -b ./aralez_x64_linux -j 200
```

---

## 2. Windows — PowerShell + WinRM

### Prerequisites
- WinRM enabled on targets (via GPO or locally: `Enable-PSRemoting -Force`)
- Admin credentials
- TrustedHosts configured (if not domain-joined):
  ```powershell
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
  ```

### Quick Start

```powershell
# Basic deployment
.\deploy\Deploy-Aralez.ps1 -TargetsFile .\targets_windows.txt -Binary .\aralez_x64_windows.exe

# With credentials and result collection
$cred = Get-Credential
.\deploy\Deploy-Aralez.ps1 `
    -TargetsFile .\targets_windows.txt `
    -Binary .\aralez_x64_windows.exe `
    -Credential $cred `
    -CollectDir .\results `
    -MaxParallel 100

# Upload results to SMB share
.\deploy\Deploy-Aralez.ps1 `
    -TargetsFile .\targets_windows.txt `
    -Binary .\aralez_x64_windows.exe `
    -OutputDest "\\fileserver\forensics\incoming"

# Use custom working directory to avoid filling C: drive
.\deploy\Deploy-Aralez.ps1 `
    -TargetsFile .\targets_windows.txt `
    -Binary .\aralez_x64_windows.exe `
    -AralezArgs "--workdir D:\Temp\triage --output \\fileserver\evidence"

# Use PsExec instead of WinRM
.\deploy\Deploy-Aralez.ps1 `
    -TargetsFile .\targets_windows.txt `
    -Binary .\aralez_x64_windows.exe `
    -UsePsExec `
    -Credential $cred
```

### WinRM vs PsExec

| Feature | WinRM | PsExec |
|---------|-------|--------|
| **Speed** | Fast (native) | Slower (SMB + service install) |
| **Setup** | `Enable-PSRemoting` | PsExec in PATH |
| **Firewall** | Port 5985/5986 | Port 445 (SMB) |
| **Authentication** | Kerberos/NTLM | NTLM |
| **Best for** | Domain environments | Legacy/non-WinRM |

### Enabling WinRM via GPO (for targets)

1. **Computer Config → Admin Templates → Windows Components → Windows Remote Management**
2. Set "Allow remote server management through WinRM" → **Enabled**
3. Add filter: `*` (all IPs)
4. **Computer Config → Windows Settings → Security → Windows Firewall**
5. Enable rule: "Windows Remote Management (HTTP-In)"

---

## 3. Ansible (Cross-Platform)

### Prerequisites
- Ansible installed: `pip install ansible`
- For Windows targets: `pip install pywinrm`
- Inventory file configured

### Inventory Examples

**Simple inventory:**
```ini
# inventory.ini
[linux_targets]
linux-01 ansible_host=10.0.1.1
linux-02 ansible_host=10.0.1.2
linux-03 ansible_host=10.0.1.3

[linux_targets:vars]
ansible_user=root
ansible_ssh_private_key_file=~/.ssh/forensic_key

[windows_targets]
win-01 ansible_host=10.0.2.1
win-02 ansible_host=10.0.2.2
win-03 ansible_host=10.0.2.3

[windows_targets:vars]
ansible_user=Administrator
ansible_password=SecurePass123
ansible_connection=winrm
ansible_port=5986
ansible_winrm_server_cert_validation=ignore
```

**Dynamic inventory from CIDR range:**
```bash
# Generate targets from a subnet scan
nmap -sn 10.0.1.0/24 -oG - | awk '/Up$/{print $2}' > targets_auto.txt
```

**Vault-encrypted credentials (recommended for production):**
```bash
# Create encrypted vault
ansible-vault create group_vars/windows_targets/vault.yml
# Add: ansible_password: SecurePass123

# Run with vault
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml --ask-vault-pass
```

### Execution

```bash
# Deploy to all hosts
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml

# Deploy to Linux only
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml --limit linux_targets

# Deploy with SFTP output
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml \
    -e "output=sftp://forensic@collector.corp/incoming"

# Deploy with custom workdir + S3 output
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml \
    -e "aralez_args='--workdir /tmp/triage --output s3://forensic-bucket/incoming \
        --s3-endpoint http://minio.corp:9000 --s3-access-key AKID --s3-secret-key SECRET'"

# High parallelism
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml -f 200

# Phased rollout: 1 host first, then batch
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml --limit linux-01
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml --limit linux_targets -f 200
```

### Ansible Performance Tuning

```ini
# ansible.cfg
[defaults]
forks = 200
timeout = 30
pipelining = True
gathering = smart

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=600s
pipelining = True
```

---

## 4. SCCM / Intune

For large enterprise Windows environments, deploy Aralez as an Application in Microsoft Endpoint Configuration Manager (SCCM) or Intune.

### SCCM Deployment

1. **Create source folder** on your SCCM distribution point:
   ```
   \\sccm-dp\Sources\Aralez\
   ├── aralez_x64_windows.exe
   └── Install-AralezSccm.ps1
   ```

2. **Create Application** in SCCM Console:
   - **Installation Program:**
     ```
     powershell.exe -ExecutionPolicy Bypass -File Install-AralezSccm.ps1 -OutputDest "\\corp-fs\evidence"
     ```
   - With custom workdir (to avoid filling C: drive):
     ```
     powershell.exe -ExecutionPolicy Bypass -File Install-AralezSccm.ps1 -OutputDest "\\corp-fs\evidence" -WorkDir "D:\Temp\triage"
     ```
   - **Detection Method** (Registry):
     - Hive: `HKEY_LOCAL_MACHINE`
     - Key: `SOFTWARE\AralezForensics`
     - Value: `LastRun` (Data Type: String)
   - **User Experience:** Install for system, whether or not user logged on
   - **Run as:** SYSTEM (64-bit)

3. **Deploy** to a Device Collection targeting the machines you want to triage.

### Intune Deployment

1. **Apps → Windows → Add → Windows app (Win32)**
2. Package the `.exe` + `.ps1` into a `.intunewin` using the Content Prep Tool
3. **Install command:**
   ```
   powershell.exe -ExecutionPolicy Bypass -File Install-AralezSccm.ps1 -OutputDest "\\corp-fs\evidence"
   ```
4. **Detection rule:** Registry key `HKLM\SOFTWARE\AralezForensics\LastRun` exists
5. **Assign** to the target device group

### Re-running After Detection Key Exists

Since the detection method uses a registry key, SCCM/Intune won't re-run Aralez if it already ran. To force a re-run:

```powershell
# On the target machine (or via SCCM script)
Remove-ItemProperty -Path "HKLM:\SOFTWARE\AralezForensics" -Name "LastRun" -ErrorAction SilentlyContinue
```

Then trigger a new Application Evaluation cycle in SCCM.

---

## 5. Group Policy (GPO) — Zero Touch

Fully automated, silent deployment that runs as SYSTEM at boot. Best for domain environments where you want **zero manual intervention**.

### Setup

1. **Prepare domain share:**
   ```
   \\dc.domain.local\NETLOGON\AralezDeploy\
   ├── aralez_x64_windows.exe
   └── Deploy-AralezGpo.bat
   ```

2. **Edit `Deploy-AralezGpo.bat`** to configure:
   ```batch
   set DEPLOY_SHARE=\\dc.domain.local\NETLOGON\AralezDeploy
   set OUTPUT_DEST=\\fileserver\evidence\incoming
   rem Optional: set WORK_DIR=D:\Temp\AralezGPO
   ```

3. **Create GPO:**
   - Open **Group Policy Management Console**
   - Create new GPO, link to the target OU(s)
   - **Computer Configuration → Policies → Windows Settings → Scripts (Startup)**
   - Add `Deploy-AralezGpo.bat` as a startup script

4. **Force immediate execution** (optional — without waiting for reboot):
   ```powershell
   # From admin workstation, push to all target machines
   $targets = Get-Content .\targets_windows.txt
   $targets | ForEach-Object {
       Invoke-Command -ComputerName $_ -ScriptBlock { gpupdate /force /target:computer }
   }
   ```

### GPO Scoping Tips

| Scope | How |
|-------|-----|
| **All domain computers** | Link GPO to domain root |
| **Specific OU** | Link GPO to target OU (e.g., `Workstations`) |
| **Specific computers** | Use WMI filter or Security Group filter |
| **Exclude DCs** | Add "Deny Apply" for Domain Controllers group |

### WMI Filter Example (x64 Windows 10+ only)

```
SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%" AND OSArchitecture = "64-bit"
```

---

## 6. Windows BITS Transfer

Use Background Intelligent Transfer Service (BITS) for downloading the binary over **constrained networks** (WAN, VPN, satellite) without saturating bandwidth.

### How BITS Works

BITS uses **idle bandwidth** to download files in the background. If the user is browsing the web, BITS pauses. If the connection drops, BITS automatically resumes where it left off.

### Single Machine

```powershell
# Basic: download from internal web server and run
powershell -ep bypass -File .\deploy\Deploy-AralezBits.ps1 `
    -SourceUri "http://internal-server.corp/aralez/aralez_x64_windows.exe"

# With upload destination and custom workdir
powershell -ep bypass -File .\deploy\Deploy-AralezBits.ps1 `
    -SourceUri "http://internal-server.corp/aralez/aralez_x64_windows.exe" `
    -OutputDest "\\fileserver\evidence" `
    -WorkDir "D:\Temp\triage"

# With S3/MinIO upload
powershell -ep bypass -File .\deploy\Deploy-AralezBits.ps1 `
    -SourceUri "http://internal-server.corp/aralez/aralez_x64_windows.exe" `
    -OutputDest "s3://forensic-bucket/incoming" `
    -S3Endpoint "http://minio.corp:9000" `
    -S3AccessKey "minioadmin" `
    -S3SecretKey "minioadmin"
```

### Multi-Machine Strategies

#### Strategy 1: BITS via WinRM (Push from admin workstation)

```powershell
$targets = Get-Content .\targets_windows.txt
$cred = Get-Credential

$targets | ForEach-Object -Parallel {
    Invoke-Command -ComputerName $_ -Credential $using:cred -FilePath .\deploy\Deploy-AralezBits.ps1 `
        -ArgumentList @(
            "-SourceUri", "http://internal-server.corp/aralez/aralez_x64_windows.exe",
            "-OutputDest", "\\fileserver\evidence",
            "-WorkDir", "D:\Temp\triage"
        )
} -ThrottleLimit 50
```

#### Strategy 2: BITS via GPO (Zero-touch, recommended for large scale)

Combine BITS with GPO for a fully hands-off deployment:

1. Host the binary on an internal web server:
   ```bash
   # On your web server
   cd /var/www/html/aralez/
   cp aralez_x64_windows.exe .
   # Binary is now at http://web.corp/aralez/aralez_x64_windows.exe
   ```

2. Edit `Deploy-AralezBits.ps1` with your source URI and output destination

3. Place the script on a domain share:
   ```
   \\dc\NETLOGON\AralezDeploy\Deploy-AralezBits.ps1
   ```

4. Create GPO → **Computer Config → Scripts → Startup → PowerShell Scripts**:
   - Script: `\\dc\NETLOGON\AralezDeploy\Deploy-AralezBits.ps1`
   - Parameters: `-SourceUri "http://web.corp/aralez/aralez_x64_windows.exe" -OutputDest "\\fileserver\evidence"`

#### Strategy 3: BITS via SCCM (Enterprise managed)

Package the BITS script as an SCCM Application:
```
powershell.exe -ExecutionPolicy Bypass -File Deploy-AralezBits.ps1 -SourceUri "http://sccm-dp/aralez/aralez_x64_windows.exe" -OutputDest "\\corp-fs\evidence"
```

#### Strategy 4: BITS via Ansible

```yaml
# Add to your Ansible playbook
- name: Run BITS deployment on Windows
  win_shell: |
    powershell -ep bypass -File C:\Temp\Deploy-AralezBits.ps1 `
        -SourceUri "http://web.corp/aralez/aralez_x64_windows.exe" `
        -OutputDest "\\fileserver\evidence"
  async: 3600
  poll: 30
```

### When to Use BITS vs Direct Push

| Scenario | Recommended Method | Why |
|----------|-------------------|-----|
| Fast LAN (>1 Gbps) | Direct push (`Deploy-Aralez.ps1`) | Faster, simpler |
| Slow WAN / VPN | **BITS** | Doesn't saturate the link |
| Remote sites (satellite) | **BITS via GPO** | Auto-resume on disconnects |
| Cloud VMs | Direct push or Ansible | Fast network, no BITS needed |
| Mixed network | BITS for remote, direct for local | Combine methods |

---

## 7. Puppet

For infrastructure-as-code environments, use the provided Puppet manifest.

### Setup

1. Add binary to module files:
   ```
   /etc/puppetlabs/code/environments/production/modules/aralez/
   ├── manifests/
   │   └── init.pp            ← deploy/aralez_puppet.pp
   └── files/
       ├── aralez_x64_linux
       └── aralez_x64_windows.exe
   ```

2. Classify nodes:
   ```puppet
   # Linux nodes
   node /^linux-/ {
     class { 'aralez':
       binary_source => 'puppet:///modules/aralez/aralez_x64_linux',
       output_dest   => 'sftp://forensic@collector.corp/incoming',
     }
   }

   # Windows nodes
   node /^win-/ {
     class { 'aralez':
       binary_source => 'puppet:///modules/aralez/aralez_x64_windows.exe',
       output_dest   => '\\fileserver\evidence\incoming',
       work_dir      => 'D:\Temp\triage',
     }
   }

   # Site-specific configuration
   node 'remote-office-01' {
     class { 'aralez':
       binary_source => 'puppet:///modules/aralez/aralez_x64_linux',
       output_dest   => 's3://forensic-bucket/remote-offices',
     }
   }
   ```

3. The module uses a `.aralez_ran` flag file to ensure triage is only collected **once**.
   To re-run: `rm /tmp/.aralez_ran` (Linux) or delete the flag file (Windows).

---

## 8. Working Directory (`-w`)

By default, Aralez creates its collection folder and zip in the **current working directory**. Use `--workdir` / `-w` to specify a different location.

### Why Use a Custom Working Directory

| Scenario | Problem | Solution |
|----------|---------|----------|
| **Small C: drive** | Collection fills the system drive | `-w D:\Temp\triage` |
| **SSD wear concerns** | Large writes to SSD | `-w E:\SpinningDisk\triage` |
| **Network appliance** | Read-only root filesystem | `-w /tmp/aralez_work` |
| **Shared workstation** | Don't want triage files in user's Desktop | `-w C:\Windows\Temp\AralezCollect` |
| **RAM disk available** | Maximum speed | `-w /dev/shm/aralez` (Linux) |

### Usage

```bash
# Linux: collect to /tmp
sudo ./aralez -w /tmp/aralez_work

# Windows: collect to D: drive
aralez.exe -w D:\Temp\triage

# Combine with upload (temp folder auto-cleaned after zip is created)
sudo ./aralez -w /tmp/aralez_work -o sftp://forensic@collector.corp/incoming
```

### Behavior

1. If the directory doesn't exist, it is **created automatically**
2. Aralez `chdir`s into the working directory before collection starts
3. All artifacts, logs, and the final zip are created there
4. The uncompressed folder is deleted after zipping
5. If `--output` is used with a remote destination, the zip is also deleted after upload

### In Deployment Scripts

```bash
# SSH
./deploy/deploy_linux.sh -t targets.txt -b ./aralez -a "--workdir /tmp/triage"

# Ansible
ansible-playbook deploy/deploy_aralez.yml -e "aralez_args='--workdir /tmp/triage'"

# GPO (in Deploy-AralezGpo.bat)
set WORK_DIR=D:\Temp\AralezGPO

# BITS
Deploy-AralezBits.ps1 -SourceUri "http://server/aralez" -WorkDir "D:\Temp\triage"
```

---

## 9. Upload Destinations (`-o`)

Aralez can upload the triage zip directly to a remote destination via `--output` / `-o`.

### Supported Destinations

| Destination | CLI Format | Feature Flag | Example |
|-------------|------------|-------------|---------|
| **Local folder** | `/path/to/folder` | None | `-o /mnt/nfs/triage` |
| **Network share** | `\\server\share\path` | None | `-o \\fileserver\evidence` |
| **SMB** | `smb://server/share/path` | None | `-o smb://fs/evidence/incoming` |
| **SFTP** | `sftp://user@host:port/path` | `upload-sftp` | `-o sftp://user@collector/triage` |
| **S3** | `s3://bucket/prefix` | `upload-s3` | `-o s3://forensic-bucket/incoming` |

### Post-Upload Cleanup Behavior

| Destination Type | Zip After Upload |
|-----------------|-----------------|
| Remote (S3, SFTP, SMB) | **Deleted** from local machine |
| Local folder (different dir) | **Moved** to destination |
| Local folder (same dir) | **Kept** in place |

> [!NOTE]
> The uncompressed collection folder is **always** deleted after the zip is created, regardless of the `--output` setting.

### Examples

```bash
# Upload to SFTP (key-based auth)
sudo ./aralez -o sftp://forensic@collector.corp/incoming

# Upload to SFTP with password (set in config.yml)
sudo ./aralez -o sftp://forensic@collector.corp:2222/triage

# Upload to SMB share (Linux — uses smbclient)
sudo ./aralez -o smb://fileserver.corp/forensics/incoming

# Upload to UNC path (Windows — uses native net use + copy)
aralez.exe -o \\fileserver\forensics\incoming

# Upload to S3 (uses env vars or IAM for credentials)
sudo ./aralez -o s3://forensic-bucket/incoming

# Upload to MinIO (self-hosted S3)
aralez.exe -o s3://triage-bucket/incoming \
    --s3-endpoint http://minio.local:9000 \
    --s3-access-key minioadmin \
    --s3-secret-key minioadmin

# Upload to local NFS mount
sudo ./aralez -o /mnt/nfs/forensics/incoming

# Full combo: custom workdir + upload + encryption
sudo ./aralez -w /tmp/triage -o sftp://collector/incoming -e MyPassw0rd
```

---

## 10. S3 / MinIO Configuration

### Credential Resolution Order

When using `-o s3://bucket/prefix`, credentials are resolved in this order:

| Priority | Source | How to Set |
|----------|--------|------------|
| 1 | **CLI arguments** | `--s3-access-key` + `--s3-secret-key` |
| 2 | **Environment variables** | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| 3 | **Shared credentials file** | `~/.aws/credentials` (via `aws configure`) |
| 4 | **IAM Instance Profile** | Automatic on EC2/ECS (no config needed) |

> [!WARNING]
> Do **not** put S3 credentials in `config.yml` — the config is embedded in the binary and would expose secrets to anyone with access to the executable.

### CLI Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--s3-endpoint` | Custom S3-compatible endpoint | `http://minio.corp:9000` |
| `--s3-access-key` | S3 access key ID | `AKIAIOSFODNN7EXAMPLE` |
| `--s3-secret-key` | S3 secret access key | `wJalrXU/K7MDENG/bPxRfi` |

### AWS S3

```bash
# Using env vars (recommended for scripts)
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=eu-west-1
sudo ./aralez -o s3://forensic-bucket/incoming

# Using IAM role on EC2 (no credentials needed)
sudo ./aralez -o s3://forensic-bucket/incoming

# Using explicit CLI args
sudo ./aralez -o s3://forensic-bucket/incoming \
    --s3-access-key AKIAIOSFODNN7EXAMPLE \
    --s3-secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### MinIO (Self-Hosted S3)

```bash
# Local MinIO instance
aralez.exe -o s3://triage-bucket/incoming \
    --s3-endpoint http://minio.local:9000 \
    --s3-access-key minioadmin \
    --s3-secret-key minioadmin

# MinIO with TLS
aralez.exe -o s3://triage-bucket/incoming \
    --s3-endpoint https://minio.corp.local:9000 \
    --s3-access-key forensicuser \
    --s3-secret-key ForensicSecretKey123
```

### Setting Up MinIO for Forensic Collection

```bash
# Install MinIO (Docker)
docker run -d \
    -p 9000:9000 -p 9001:9001 \
    -e MINIO_ROOT_USER=minioadmin \
    -e MINIO_ROOT_PASSWORD=minioadmin \
    -v /data/minio:/data \
    minio/minio server /data --console-address ":9001"

# Create the bucket (via mc CLI)
mc alias set local http://localhost:9000 minioadmin minioadmin
mc mb local/triage-bucket

# Create a dedicated forensic upload user with limited permissions
mc admin user add local forensicuser ForensicUploadKey123
mc admin policy attach local writeonly --user forensicuser
```

### In Deployment Scripts

```powershell
# PowerShell (set env vars before running the deployment)
$env:AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
$env:AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG"
$env:AWS_DEFAULT_REGION = "eu-west-1"
.\deploy\Deploy-Aralez.ps1 -TargetsFile .\targets.txt -Binary .\aralez.exe `
    -AralezArgs "--output s3://forensic-bucket/incoming"

# Ansible (pass via environment)
ansible-playbook deploy/deploy_aralez.yml \
    -e "aralez_args='--output s3://bucket/incoming --s3-endpoint http://minio:9000 --s3-access-key AKID --s3-secret-key SECRET'"
```

---

## 11. Result Collection Strategies

### Strategy Comparison

| Strategy | Transfers | Centralized | Offline Targets | Scale |
|----------|----------|-------------|-----------------|-------|
| **SCP/Collect** (`-C`) | Admin pulls from each host | No | Must be online | Small |
| **SMB share** | Each host pushes | Yes | No | Medium |
| **SFTP** | Each host pushes | Yes | No | Large |
| **S3 / MinIO** | Each host pushes | Yes | No | Very large |
| **NFS / CIFS mount** | Each host writes locally | Yes | No | Large |
| **GPO + BITS + SMB** | Auto download + auto push | Yes | Runs at next boot | Very large |

### Recommended Architecture by Scale

**Small scale — Direct collection:**
```bash
./deploy/deploy_linux.sh -t targets.txt -b ./aralez -C ./results/
# Results land in ./results/ on your admin workstation
```

**Medium scale — Central SMB/SFTP:**
```bash
# Each host uploads directly to the SFTP collector
./deploy/deploy_linux.sh -t targets.txt -b ./aralez \
    -a "--output sftp://forensic@collector.corp/incoming"
```

**Large scale — S3/MinIO:**
```bash
# Massively parallel, each host uploads independently
ansible-playbook -i inventory.ini deploy/deploy_aralez.yml -f 500 \
    -e "aralez_args='--output s3://forensic-bucket/incoming --s3-endpoint http://minio:9000 --s3-access-key KEY --s3-secret-key SECRET'"
```

**Very large scale — GPO + BITS + S3:**
No admin workstation needed. Each machine:
1. Downloads the binary via BITS at boot (GPO startup script)
2. Runs triage
3. Uploads zip to S3/MinIO
4. Cleans up locally

---

## 12. Architecture Decision Guide

### Choosing Your Deployment Method

```
                               ┌─── Active Directory? ───┐
                               │                          │
                              YES                        NO
                               │                          │
                    ┌──── Scale? ────┐              ┌─── OS? ───┐
                    │                │              │            │
                 Small           Large          Linux        Windows
                    │                │              │            │
              PowerShell          GPO/SCCM     SSH script    Ansible
              + WinRM            + BITS         (direct)    + WinRM
```

### Network Topology Considerations

| Topology | Recommended | Why |
|----------|-------------|-----|
| **Single site, fast LAN** | SSH/WinRM direct push | Simple, fast |
| **Multi-site, WAN links** | BITS + central S3/MinIO | No bandwidth saturation |
| **VPN-connected laptops** | BITS via GPO | Runs at next login, auto-resume |
| **Air-gapped network** | USB + local folder output | `aralez -o /mnt/usb/evidence` |
| **Cloud VMs (AWS/Azure)** | Ansible + S3 IAM roles | No credentials needed |
| **Mix of on-prem + cloud** | Ansible + S3 endpoint | Unified collection point |

---

## 13. Security Considerations

### Credential Handling

| Method | Credentials | Best Practice |
|--------|------------|--------------|
| SSH | Key-based | Use dedicated forensic SSH key |
| WinRM | Kerberos/NTLM | Use dedicated forensic service account |
| Ansible | Vault-encrypted | `ansible-vault` for passwords |
| S3 | IAM / CLI args | Use IAM roles on cloud, CLI args on-prem |
| BITS | None (HTTP download) | Host binary on internal server only |
| GPO/SCCM | SYSTEM account | Runs natively, no extra creds |

### Network Security

- **BITS source:** Host the binary on an **internal** web server only. Do not expose to the internet.
- **SFTP/SMB:** Use dedicated forensic accounts with **upload-only** permissions.
- **S3:** Use IAM policies that allow only `s3:PutObject` — never `s3:GetObject` or `s3:DeleteObject`.
- **Encryption:** Use `-e <password>` to encrypt the zip with AES-GCM before upload.

### Minimal S3 IAM Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::forensic-bucket/incoming/*"
    }]
}
```

---

## 14. Performance Benchmarks

| Scale | Method | Parallel | Estimated Time* |
|-------|--------|----------|----------------|
| Small | SSH / WinRM | 50 | Minutes |
| Medium | SSH / WinRM | 100 | Minutes |
| Large | SSH / Ansible | 200 | Tens of minutes |
| Very large | Ansible + S3 | 500 | Under an hour |
| Massive | GPO + BITS + S3 | All at boot | Hours |

*Times depend on network speed, artifact volume (typical: 50–200 MB per host), and host performance.*

### Bottleneck Analysis

| Bottleneck | Symptom | Solution |
|-----------|---------|----------|
| **Admin workstation** | High CPU, slow dispatch | Increase parallelism, use GPO/SCCM |
| **Network bandwidth** | Slow uploads | Use BITS, compress, or stage locally |
| **Target disk I/O** | Slow collection | Use `-w` with faster disk, reduce artifact scope |
| **Upload server** | S3/SFTP overloaded | Scale MinIO, use S3 multi-part upload |
| **Too many SSH connections** | "Too many open files" | Reduce `-j`, increase `ulimit -n` |

---

## 15. Troubleshooting

| Issue | Solution |
|-------|----------|
| **SSH timeout** | Increase timeout with SSH config or `-p 22` |
| **WinRM connection refused** | Run `Enable-PSRemoting -Force` on targets |
| **Permission denied** | Ensure root/admin access, check SSH keys or credentials |
| **Too many open files** | Reduce parallel jobs (`-j 30`) or increase `ulimit -n 65536` |
| **Binary arch mismatch** | Use `aralez_x86_*` for 32-bit machines |
| **C: drive full during triage** | Use `--workdir D:\Temp\triage` to collect on a different drive |
| **BITS transfer stalls** | Check BITS service is running: `Get-Service BITS` |
| **S3 upload fails** | Verify endpoint URL uses `http://` not `https://` for non-TLS MinIO |
| **"os error 123" on Windows** | Use forward slashes `s3://` not backslashes `s3:\` |
| **Feature not available** | Rebuild with the required feature: `cargo build --features upload-s3` |
| **Upload succeeds, zip not deleted** | Normal when `-o` points to the same local directory |
| **Ansible "unreachable"** | Check `ansible_connection=winrm` for Windows hosts |
| **GPO not applying** | Run `gpresult /r` on target to verify GPO is linked |
| **Puppet "already ran"** | Delete flag file: `rm /tmp/.aralez_ran` |
| **MinIO "Access Denied"** | Verify bucket exists and user has `writeonly` policy |
| **SFTP "Host key verification"** | Add host key: `ssh-keyscan collector.corp >> ~/.ssh/known_hosts` |
