<div align="center">
  <img src="./assets/logo.png" alt="Aralez Logo" width="280" />

  <h1>Aralez</h1>
  <strong>Cross-Platform Forensic Triage &amp; Artifact Collection</strong>

  <p>
    <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge&logo=apache" alt="License"></a>
    <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platform">
    <img src="https://img.shields.io/badge/Rust-2021-orange?style=for-the-badge&logo=rust" alt="Rust">
    <img src="https://img.shields.io/badge/single_binary-no_dependencies-brightgreen?style=for-the-badge" alt="Single binary">
  </p>

  <p>
    <em>One binary. No installer. No runtime. Raw-disk access, streaming archives, and cloud delivery.</em>
  </p>
</div>

---

**Aralez** is a forensic triage collector written in **Rust**. It drops onto an endpoint as a *single self-contained executable* (configuration, tooling and collection logic all embedded), reads the filesystem at the raw level, and produces one archive ready for your analysis pipeline.

It is built for the two things that make triage at scale painful: **collecting files the OS won't let you copy**, and **doing it on ten thousand machines without babysitting any of them**.

```bash
# Windows (Administrator)          Linux / macOS (root)
aralez_x64_windows.exe             sudo ./aralez_x64_linux
```

---

## Table of Contents

- [Why Aralez](#why-aralez)
- [Quick Start](#quick-start)
- [Platform & Filesystem Support](#platform--filesystem-support)
- [The Collection Engine](#the-collection-engine)
- [The Execution Engine](#the-execution-engine)
- [Output, Packaging & Encryption](#output-packaging--encryption)
- [Remote Delivery](#remote-delivery)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Reconfigure Without Recompiling](#reconfigure-without-recompiling)
- [Safety Rails](#safety-rails)
- [Enterprise Deployment](#enterprise-deployment)
- [Building from Source](#building-from-source)
- [Documentation](#documentation)
- [Contributing & License](#contributing--license)

---

## Why Aralez

| | |
|---|---|
| 🔬 **Raw filesystem access** | Parses **NTFS** and **ext4** structures directly off the volume device, bypassing the file API entirely. Collects `$MFT`, `$Boot`, `$UsnJrnl`, registry hives, Alternate Data Streams, INDX and file slack, including locked and in-use files. |
| 🌪️ **Zero-folder streaming** | `--stream` pipes every artifact straight into the archive as it is read. No staging directory, roughly **half the disk footprint**, and nothing sensitive left behind mid-run. |
| 🧊 **Crash-resilient archives** | `--compression tar` writes `.tar.zst`. ZIP writes its index last, so a killed process leaves an unreadable file; TAR is a flat stream, so everything already flushed still extracts. |
| 🥷 **Silent operation** | `--silent` suppresses collection output for GPO/SCCM/cron execution. Logs still land inside the archive. |
| ⏹️ **Interruption-safe** | First `Ctrl+C` finalizes the archive with everything collected so far. Second `Ctrl+C` force-quits. |
| 📦 **Self-contained binary** | Config, Sysinternals tooling and collectors are embedded in the executable. Windows builds link the CRT statically: no redistributable, no install. |
| 🔁 **Reconfigurable in place** | Swap the embedded YAML config into an existing binary with one flag. No Rust toolchain, no rebuild. |
| ☁️ **Direct evidence delivery** | Ship the archive to **S3 / MinIO, SFTP, SMB** or a file share straight from the endpoint, and have the local copy removed once it lands. |
| 🛡️ **Resource-aware** | RAM and disk pre-flight checks, per-task timeouts and memory caps, and global size limits so triage never fills a production disk. |

---

## Quick Start

Aralez requires **Administrator** on Windows and **root** on Linux/macOS; it exits immediately otherwise.

```bash
# Full collection using the embedded configuration
sudo ./aralez

# Stream artifacts directly into the archive (no staging folder)
sudo ./aralez --stream

# Crash-proof streaming archive (.tar.zst)
sudo ./aralez --stream --compression tar

# Fully silent, for GPO / SCCM / cron
sudo ./aralez --stream --silent

# Encrypt the archive and push it to a collection server
sudo ./aralez --stream -e 'S3cret!' -o sftp://ir@collector.corp/incoming
```

Inspect or validate before you deploy:

```bash
./aralez --show_config      # print the embedded YAML
./aralez --check_config     # validate it and exit
./aralez --verbos           # verbose logging
```

The result is a single archive named from your `output_filename` template, by default `Aralez_<hostname>_<YYYY-MM-DD_HH-MM-SS>.zip`.

---

## Platform & Filesystem Support

Aralez identifies the volume by reading its signature directly (NTFS → APFS → HFS+ → ext4), then selects a collection engine.

| Engine | Access | Windows | Linux | macOS |
|---|---|:---:|:---:|:---:|
| **NTFS** | Raw MFT parsing off the volume device | ✅ | ✅ | - |
| **ext4** | Raw inode parsing off the block device | - | ✅¹ | - |
| **POSIX fallback** | Standard OS file API | - | ✅ | ✅ |

¹ ext4 is parsed raw only for a real block device path (`/dev/…`); a mount-point path uses the POSIX explorer.

> **NTFS from Linux.** The NTFS engine is compiled for Linux as well as Windows, so a Linux responder can raw-parse an attached NTFS volume, which is the intended path for dead-box triage of Windows disks.

> **macOS is POSIX-based.** APFS and HFS+ explorers exist in the tree, but their traversal routines are **unimplemented stubs** that collect nothing. In practice this is moot: SIP blocks opening `/dev/diskXsY`, so macOS always passes a mount point, which routes to the POSIX fallback explorer. Expect no raw-device capabilities on macOS.

**Automatic degradation.** On Linux, if an ext4 volume reports *missing required journal features* or a *corrupt filesystem*, Aralez logs a warning and transparently re-runs the collection through the POSIX explorer rather than failing the run.

**Target device.** `-d/--default_drive` selects what to process: a drive letter on Windows (default `C`), a block device such as `/dev/sda1` on Linux, or a device basename on macOS. Left unset on Linux/macOS, Aralez resolves the root device itself from `/proc/self/mountinfo`, `/proc/mounts` or `mount`. A task may set `drive: "*"` to sweep every NTFS volume from `A:` to `Z:`, honouring `exclude_drives`. **Windows only**; it is a no-op elsewhere.

**Not supported**, stated plainly so you don't plan around it: no VSS/shadow-copy access, no deleted-file carving or unallocated-space recovery, no GPT/MBR or physical-disk (`\\.\PhysicalDrive*`) parsing, no E01/dd image ingest, and no FAT/exFAT/ReFS/XFS/btrfs/ZFS engines.

---

## The Collection Engine

A `collect` task walks the filesystem tree and matches artifacts against glob patterns.

```yaml
artifacts:
  type: "collect"
  priority: 1
  output_folder: "{{root_output_path}}\\{{drive}}"
  entries:
    mft:
      - root_path: "\\"
        objects: ["$MFT", "$Boot"]
    event_logs:
      - root_path: "\\Windows\\System32\\winevt\\Logs"
        objects: ["*.evtx"]
    user_hives:
      - root_path: "\\Users\\*"
        objects: ["*.DAT"]
```

**What the engine gives you:**

- **Glob matching**: `*`, `**`, `?` and `[…]` are supported in both `root_path` and `objects`. Patterns in `root_path` are automatically split into a literal root plus a pattern, so `/home/*/.ssh` works as written.
- **Environment variables**: `root_path` may start with `%` and reference environment variables (e.g. `%SystemRoot%`), expanded at runtime.
- **Size caps**: `max_size` is resolved as the **minimum** of the entry, task and global values, so a global ceiling can never be exceeded by a single entry.
- **Per-entry encryption**: see [Two layers of encryption](#two-layers-of-encryption).
- **Loop protection**: visited-path sets and per-directory dedup by MFT record number keep `**` recursion bounded; the POSIX explorer additionally skips anything inside its own output directory.

Validation happens at parse time: `root_path` must begin with `\`, `/` or `%`; duplicate entry names, zero `max_size` and empty `encrypt` passwords are all rejected before collection starts.

### What raw NTFS access buys you

The NTFS engine opens the *volume* (`\\.\C:`) and parses the filesystem itself; it never calls `CreateFile` on the target. Sharing violations and mandatory locks simply don't apply, and several artifacts become reachable that no file copy can produce:

| Capability | Detail |
|---|---|
| **Locked & in-use files** | Registry hives, EVTX, browser databases and live metafiles collect while the OS holds them open |
| **NTFS metafiles** | `$MFT`, `$LogFile`, `$Secure` (`:$SDS`/`:$SDH`/`:$SII`), `$Extend\$UsnJrnl:$J`, all invisible to the Win32 API |
| **`$Boot`** | Special-cased: read as the first 8192 bytes straight off the volume device |
| **Alternate Data Streams** | Request one as `objects: ["file.txt:Zone.Identifier"]`; written out as `file.txt_Zone.Identifier` |
| **INDX slack** | Every `$INDEX_ALLOCATION` attribute is dumped alongside the file as `<name>_<attr>.idx`, the classic source of deleted-entry filenames and timestamps |
| **File slack** | Bytes past the valid-data-length are split into a separate `<name>.FileSlack` entry and the main file zero-padded, so offsets stay faithful |

> ⓘ ADS, INDX, slack and metafile collection are **NTFS-only**. The ext4 and POSIX explorers parse the same `file:stream` syntax but never read a stream. Symlinks are skipped rather than followed or recreated on every engine, and permissions/ACLs are not reproduced. Capture `$Secure:$SDS` (NTFS) or `/etc/passwd`-class files (Linux) if you need them.

### Artifact coverage out of the box

The shipped templates in [`config/`](config/) are ready-to-run triage profiles:

- **Windows**: `$MFT`, `$Boot`, `$Extend`, `$Recycle.Bin`, EVTX logs, SAM/SYSTEM/SOFTWARE/SECURITY/DEFAULT hives, user `NTUSER.DAT`, Amcache, Prefetch, scheduled tasks, WER reports, WMI repository & traces, BITS, firewall logs, PowerShell history, LNK/Recent, startup folders, browser history, and password-protected capture of executables and Office documents from user-writable paths.
- **Linux**: shell histories and profiles, SSH keys and configs, PAM, cron/at/systemd/init.d persistence, auditd rules, `/var/log` (incl. journal), nginx/Apache configs, `/etc` system identity, `/proc` state, container and cloud credential artifacts, world-writable temp directories.
- **macOS**: Unified Logs, FSEvents, KnowledgeC, Biome, quarantine DB, Spotlight, **TCC**, authorization DB, LaunchAgents/LaunchDaemons, login & startup items, periodic scripts, audit logs, install history, app bundle metadata, Safari/Chrome/Firefox/Edge history, keychains, kexts, XProtect, crash reports and FileVault configuration.

---

## The Execution Engine

An `execute` task runs commands and captures their output. Entries within a task run **in parallel** (Rayon), while tasks themselves run sequentially in `priority` order.

Three execution types:

| `exec_type` | What it is | Platforms |
|---|---|---|
| `internal` | Collectors compiled into Aralez, with no external binary and no process spawn | All |
| `system` | A binary already present on the host (`netstat.exe`, `/bin/ps`, `/usr/bin/sw_vers`, …) | All |
| `external` | A tool **embedded inside the Aralez executable**, extracted and run at collection time | **Windows only**; rejected at config-parse time elsewhere |

### Built-in `internal` collectors

Names are matched exactly and are case-sensitive; an unknown name logs an error and is skipped.

| Name | Platform | Collects |
|---|---|---|
| `ProcInfo` | Windows | Toolhelp32 process snapshot: PID, parent PID, executable |
| `ProcDetailsInfo` | Windows | JSON: PID, parent, threads, priority, image path, memory, creation time, **MD5 + SHA-256 of the on-disk image**, loaded modules |
| `PortsInfo` | Windows | TCP connection table. **IPv4 TCP only**, no UDP/IPv6 |
| `ProcInfo` | Linux | 25-column CSV from `/proc`: `stat`, `cmdline`, `status`, `io`, `exe`/`cwd`/`root` links, MD5 of the executable |
| `Network` | Linux | CSV from `/proc/net/{tcp,tcp6,udp,udp6}`: endpoints, state, uid, inode |
| `Memory` | Linux | **Hidden-process detection** (`ps -e` diffed against `/proc`), kernel modules, suspicious `rw-p`/stack/heap mappings |
| `SystemInfo` | Linux | OS release, kernel, hostname, uptime, CPU/memory, disks, interfaces |
| `PackageManager` | Linux | dpkg inventory and APT/YUM repository configuration |
| `ProcInfo` | macOS | 19-column CSV via `libproc`: memory, threads, CPU time, faults, syscalls, exe path, MD5 |
| `ProcDetailsInfo` | macOS | Per-process open file descriptors and their types (vnode/socket/pipe/…) |

The macOS templates fill the remaining gaps with `system` entries rather than internal collectors.

> ⓘ Only **stdout** is captured; stderr is discarded, so a tool that reports to stderr yields an empty output file. Internal collectors always write to disk first and are copied into the archive afterwards, even under `--stream`.

### Embedded `external` tools (Windows)

Compiled into the binary and extracted on demand: `autorunsc.exe`, `handle.exe`, `tcpvcon.exe`, `pslist.exe`, `Listdlls.exe`, `PsService.exe`, `pipelist.exe`, plus `winpmem.exe` for memory acquisition when built with the `extended-tools` or `memdump` feature.

You can add and remove embedded tools on an existing binary without rebuilding:

```powershell
aralez.exe --list_tools                            # show static + dynamic tools
aralez.exe --add_tool C:\ir\mytool.exe out.exe     # embed a new tool
aralez.exe --remove_tool mytool.exe out.exe        # strip one out
```

### Chaining execution into collection

`link` feeds a command's output back into a `collect` task. Each output line is treated as a file path, cleaned and de-duplicated, then collected with the full raw engine. This is how you go from *"list the service binaries registered by event 7045"* to *"and collect every one of them"*:

```yaml
- name: "powershell"
  args: ["-command", "Get-WinEvent -LogName System -FilterXPath '*[System[(EventID=7045)]]' | ..."]
  output_file: "ComputerInfo.txt"
  exec_type: "system"
  link: "services"        # → the `services` collect task pulls those binaries
```

The linked task (`services` above) is declared as a `collect` task with an `output_folder` and **no entries**; they are supplied entirely by the link.

> ⓘ `link` works with `exec_type: system` and `external` only. Internal collectors return no captured output, so a `link` on one never fires. Path extraction is also Windows-shaped (it truncates each line at the first `.exe`/`.dll`/`.sys` and strips the drive letter), so the feature is not practically usable on Linux/macOS as written.

---

## Output, Packaging & Encryption

### Streaming vs. staged

| | Staged (default) | Streaming (`--stream`) |
|---|---|---|
| Artifacts written to disk first | Yes, then compressed | **No**, compressed in flight |
| Peak disk usage | ~2× collection size | ~1× |
| Staging folder | Removed after archiving | Never created |

### Archive formats

| Format | Flag | Notes |
|---|---|---|
| **ZIP** (default) | `--compression zip` | Deflate, Zip64 for large files, optional **AES-256** encryption |
| **TAR + Zstandard** | `--compression tar` | `.tar.zst` at zstd level 3, single-threaded. Remains readable if the process is killed mid-write, which ZIP cannot do because its central directory is written last. |

The effective config (`config.yml`) is written into the archive first, and the run log is added last, so every archive is self-documenting.

> ⓘ TAR's crash resilience covers everything already flushed to the OS. The zstd encoder and its buffer are not flushed on a schedule, so a hard kill still loses whatever is in flight.

### Logging

Every run writes `<output_filename>.log` in the working directory, then moves it **inside the archive** at the end, so the log travels with the evidence. `-v/--verbos` additionally echoes those lines to stdout.

`--silent` suppresses collection progress and status output. It does **not** gate the upload backends, which print through directly. A successful upload still reports on stdout under `--silent`.

### Two layers of encryption

Aralez encrypts at two independent levels. They are unrelated mechanisms and behave differently:

**1. Archive-level**: `-e/--encrypt <PASSWORD>`, or top-level `encrypt:` in config (CLI wins).
Applies **WinZip AES-256** to the whole archive.

> ⚠️ **Archive encryption is ZIP-only.** The TAR path accepts no password, so combining `-e` with `--compression tar` silently produces an *unencrypted* `.tar.zst`. Use ZIP whenever you need an encrypted archive.

**2. Per-entry**: `encrypt:` inside a collection entry, **NTFS collection only**.
Individual artifacts are wrapped with AES-256-GCM (key = `SHA-256(password)`, 12-byte nonce prepended) and get a `.enc` extension. Its purpose in the shipped templates is *sample handling*: keeping endpoint AV from quarantining or gutting collected malware in transit:

```yaml
suspicious_files:
  - root_path: "\\Users\\*\\Downloads"
    objects: ["*.exe", "*.dll", "*.ps1", "*.docm", "*.js"]
    max_size: 5242880
    encrypt: "infected"     # → sample.exe.enc
```

> ⓘ Per-entry `encrypt` is implemented only in the NTFS reader. The ext4 and POSIX-fallback engines accept the key and ignore it, so those entries are collected in the clear. Treat this as sample-safety packaging, not as a confidentiality control; for confidentiality, encrypt the archive.

---

## Remote Delivery

Point `-o/--output` at a destination and Aralez ships the archive straight from the endpoint.

```bash
# SFTP: user@host, optional :port
sudo ./aralez -o sftp://forensic@collector.corp/incoming
sudo ./aralez -o sftp://forensic@collector.corp:2222/incoming

# AWS S3
sudo ./aralez -o s3://forensic-bucket/evidence/

# S3-compatible (MinIO, Ceph, Wasabi …)
sudo ./aralez -o s3://bucket/prefix \
    --s3-endpoint "https://minio.corp:9000" \
    --s3-access-key "KEY" --s3-secret-key "SECRET"

# SMB share
aralez.exe -o smb://fileserver/forensics/incoming

# Any local or mounted path
sudo ./aralez -o /mnt/evidence/
```

| Backend | URI scheme | Cargo feature | Credentials |
|---|---|---|---|
| S3 / S3-compatible | `s3://bucket/prefix` | `upload-s3` | CLI flags, config keys, or the ambient AWS credential chain (env, `~/.aws/credentials`, instance profile) |
| SFTP | `sftp://user@host[:port]/path` | `upload-sftp` | `key_path` → `password` → SSH agent |
| SMB | `smb://server/share/path` | *(always compiled)* | `username` / `password` / `domain` via config |
| Folder | any path without a scheme | *(always compiled)* | - |

If a backend was not compiled in, Aralez fails with the exact rebuild command rather than silently skipping the upload.

**Backend-specific notes worth knowing before you deploy:**

- **SFTP via `-o` can only authenticate through an SSH agent.** The CLI URI carries no password or key path, so agent auth is the only route; use a config destination when you need `key_path` or `password`. SFTP transfers stream in 8 MiB chunks and **do not verify host keys**.
- **SMB on Linux/macOS shells out to `smbclient`**, which must be installed on the endpoint. On Windows it uses `net use` + `copy`, and the `domain` key is ignored. With no credentials it relies on the caller's existing token, which is what you want under SYSTEM/GPO.
- **S3** uploads via a single `put_object` (no multipart). A custom `--s3-endpoint` also forces path-style addressing, which is what MinIO and Ceph expect. There is no CLI flag for `region`; set it in config.
- **UNC paths** written as `\\server\share` go through the *folder* backend, not SMB.

**Multiple destinations** can be declared in config, and are attempted independently, so one failure does not abort the others:

```yaml
output:
  destinations:
    - type: s3
      bucket: "ir-evidence"
      prefix: "2026/case-1234/"
      region: "eu-west-1"
    - type: sftp
      host: "collector.corp"
      port: 22
      username: "forensic"
      key_path: "/root/.ssh/id_ed25519"
      remote_path: "/incoming"
    - type: folder
      path: "/mnt/backup"
```

**Precedence and cleanup:**

- `-o/--output` **replaces** config destinations entirely; they are not also attempted. `--s3-*` flags override matching config values.
- Config destinations are attempted independently; a failure is logged and the next is tried.
- The local archive is deleted **only** when `-o` was used: always for a remote scheme, and for a local path only when it resolves to a different directory than the archive's own (so the net effect is a move). Config-driven destinations never delete the local copy.

---

## CLI Reference

### Common

| Flag | Description |
|---|---|
| `-v, --verbos` | Verbose logging |
| `-s, --show_config` | Print the embedded configuration and exit |
| `-x, --check_config` | Validate the embedded configuration and exit |
| `-c, --change_config <CONFIG> <OUTPUT>` | Write a new binary with a different embedded config |
| `-e, --encrypt <PASSWORD>` | AES-256 encrypt the ZIP archive |
| `-o, --output <DESTINATION>` | Deliver to `s3://`, `smb://`, `sftp://` or a path |
| `-w, --workdir <PATH>` | Working directory for collection (created if missing) |
| `-d, --default_drive <DRIVE>` | Target drive letter (Windows, default `C`) or device (`/dev/sda1`) |
| `--stream` | Compress on the fly, no staging folder |
| `--compression <zip\|tar>` | Archive format (default `zip`) |
| `--silent` | Suppress collection output (upload backends still print) |
| `--s3-endpoint <URL>` | S3-compatible endpoint |
| `--s3-access-key <KEY>` | S3 access key ID |
| `--s3-secret-key <SECRET>` | S3 secret access key |

### Windows only

| Flag | Description |
|---|---|
| `-a, --add_tool <TOOL> <OUTPUT>` | Embed an executable into a new binary |
| `-r, --remove_tool <NAME> <OUTPUT>` | Remove an embedded tool |
| `-l, --list_tools` | List embedded tools (static and dynamic) |

CLI flags override their config-file equivalents.

---

## Configuration

Aralez is driven by a YAML file **embedded in the binary**. The shipped templates are:

| File | Target |
|---|---|
| [`config/config_windows.yml.template`](config/config_windows.yml.template) | Windows |
| [`config/config_linux.yml.template`](config/config_linux.yml.template) | Linux |
| [`config/config_macos.yml.template`](config/config_macos.yml.template) | macOS 12 to 15 |

### Top level

| Key | Type | Default | Description |
|---|---|---|---|
| `tasks` | map | - | **Required.** Named tasks, executed in `priority` order |
| `output_filename` | string | - | **Required.** Supports `{{hostname}}` and `{{datetime}}` |
| `version` | string | - | Free-form config version label |
| `max_size` | int | unlimited | Global artifact size ceiling; see [note on units](#a-note-on-max_size) |
| `memory_limit` | int (MB) | `1024` | Minimum available RAM required to start |
| `disk_limit` | int (MB) | `8192` | Disk budget for the collection |
| `disk_path` | string | `C:\` / `/` | Filesystem used for the disk check |
| `encrypt` | string | - | Archive password (AES-256, ZIP only) |
| `stream` | bool | `false` | Stream mode |
| `compression` | string | `"zip"` | `"zip"` or `"tar"` |
| `output` | object | - | Upload destinations |

### Task level

| Key | Type | Description |
|---|---|---|
| `type` | `collect` \| `execute` | **Required.** |
| `priority` | int 0-255 | Execution order; unset sorts last (`255`) |
| `disabled` | bool | Skip this task |
| `drive` | string | Target drive/device; `"*"` sweeps all NTFS volumes (Windows only) |
| `exclude_drives` | list | Drives to skip when `drive: "*"` |
| `output_folder` | string | Destination inside the archive; supports `{{root_output_path}}`, `{{drive}}` |
| `max_size` | int | Task-level size cap. **MB** on `execute`, bytes on `collect` |
| `memory_limit` | int (MB) | Memory cap for executed tools (**Windows only**) |
| `timeout` | int (s) | Per-tool timeout; no default |
| `entries` | map | Named groups of entries |

### Entry level

| Key | Applies to | Description |
|---|---|---|
| `root_path` | collect | Base path; must start with `\`, `/` or `%` |
| `objects` | collect | Glob patterns; `name:stream` selects an ADS (NTFS only) |
| `type` | collect | `"glob"`; requires `root_path` + `objects` |
| `max_size` | collect | Per-entry size cap, in **bytes** |
| `encrypt` | collect | Per-file password (NTFS only) |
| `name` | execute | Tool name or absolute path |
| `args` | execute | Argument list; supports `{{root_output_path}}` |
| `output_file` | execute | Captured-output filename |
| `exec_type` | execute | `internal` \| `system` \| `external` |
| `link` | execute | Collect task fed by this tool's output |

Config files are read as UTF-8, UTF-16LE/BE with BOM, or BOM-less UTF-16LE, with CRLF normalised, so a config edited in Notepad or exported from PowerShell loads without conversion.

---

## Reconfigure Without Recompiling

The embedded config lives in a Windows PE resource, or between `===CONFIG_START===` / `===CONFIG_END===` markers appended to the ELF/Mach-O binary. Either way you can retarget a **released** binary for a new investigation without a Rust toolchain:

```bash
# Produce a new binary carrying your custom collection profile
./aralez -c ./my_incident_config.yml ./aralez_case1234

# Verify before deploying
./aralez_case1234 --show_config
./aralez_case1234 --check_config
```

This is the intended workflow for per-case profiles: build once, tailor per incident, deploy the tailored binary. To bake a profile in at compile time instead, see [`CONFIG_FILE`](#choosing-the-embedded-config-at-build-time).

If no config is embedded, Aralez falls back to the profile compiled in at build time.

---

## Safety Rails

Triage runs on production machines, so Aralez refuses to be the reason one falls over:

- **Pre-flight RAM check**: Aralez exits before collecting anything if available memory is below `memory_limit` (default 1024 MB; the shipped templates set 512). Read from `MemAvailable` on Linux and `GlobalMemoryStatusEx` on Windows. On macOS the check uses *total* physical RAM as a proxy and fails open.
- **Disk guard**: re-evaluated *before every task* against `disk_limit` (default 8192 MB) on `disk_path`. When the budget is exhausted, collection stops cleanly and the archive is finalised with what has already been gathered.
- **Per-task timeout**: `timeout: <seconds>` kills a hung external tool and its whole process group. There is **no default**, so leaving it unset lets a tool run forever. The check runs between reads of the tool's stdout, so a process that neither writes nor exits cannot be timed out.
- **Per-task memory limit**: `memory_limit` on an `execute` task is enforced via a Windows Job Object. On Linux and macOS the value is accepted and **silently ignored**, with no rlimit and no cgroup.
- **Output size cap**: when a tool exceeds the task's `max_size`, it is killed and the truncated output is kept rather than discarded.
- **Layered size caps**: the minimum of entry/task/global `max_size` always wins.
- **Graceful interrupt**: the first `Ctrl+C` sets a flag polled between tasks and inside NTFS/ext4 traversal, so the archive is finalised with everything collected so far. A second `Ctrl+C` exits immediately **without** finalising. In-flight `execute` tasks are not interruptible, and the flag does not skip a configured upload.
- **Automatic cleanup**: staging folders and the on-disk log are removed after archiving; extracted external tools are deleted after they run; the archive is removed after a successful `--output` upload.

### Timestamps

Original **modification times** are preserved for NTFS collection in **folder mode only**. In direct stream mode (`--stream`) archive entries carry no preserved mtime; ZIP entries use defaults and TAR headers set only size and mode `0644`. Access, creation and change times are never preserved on any engine.

> If timestamp fidelity matters more than disk footprint, collect to a folder and let Aralez archive it afterwards; that path carries mtimes into both ZIP and TAR.

### A note on `max_size`

The key is read with **different units** by the two subsystems, so copy the shipped templates rather than reasoning from first principles:

| Context | Unit |
|---|---|
| `collect` entries | **bytes** (`max_size: 5242880` = 5 MB) |
| `execute` tasks | **megabytes** (`max_size: 5000` = 5 GB) |

Entry-level `max_size` on an `execute` entry is ignored; only the task-level and global values apply there.

---

## Enterprise Deployment

Ready-to-use scripts live in [`deploy/`](deploy/):

### Windows

| Script | Purpose |
|---|---|
| [`Deploy-Aralez.ps1`](deploy/Deploy-Aralez.ps1) | Fleet deployment over WinRM or PsExec, with result collection |
| [`Deploy-AralezBits.ps1`](deploy/Deploy-AralezBits.ps1) | Pull the binary via BITS and run silently |
| [`Deploy-AralezGpo.bat`](deploy/Deploy-AralezGpo.bat) | GPO startup-script wrapper |
| [`Install-AralezSccm.ps1`](deploy/Install-AralezSccm.ps1) | SCCM / Intune packaging |
| [`Invoke-AralezTriage.ps1`](deploy/Invoke-AralezTriage.ps1) | Single-host triage helper |

### Linux / cross-platform

| Script | Purpose |
|---|---|
| [`deploy_linux.sh`](deploy/deploy_linux.sh) | Parallel SSH deployment (50 concurrent by default, tunable to 500+), with dry-run |
| [`deploy_aralez.yml`](deploy/deploy_aralez.yml) | Ansible playbook covering Linux **and** Windows hosts |
| [`aralez_puppet.pp`](deploy/aralez_puppet.pp) | Puppet manifest |

```bash
# Deploy to a fleet over SSH and collect results via SFTP
./deploy/deploy_linux.sh -t targets.txt -b ./aralez_x64_linux \
    -a "--stream --output sftp://user@collector/triage" -j 100
```

> ⚠️ The result-collection paths in the deploy scripts glob for `*.zip`. If you pass `--compression tar`, retrieve the `.tar.zst` files yourself or push them with `--output` instead.

> 📚 Full step-by-step guides, WinRM setup, inventory examples and scaling advice: [**`deploy/DEPLOYMENT.md`**](deploy/DEPLOYMENT.md)

---

## Building from Source

Cargo features keep the core binary small; heavy dependencies are opt-in.

```bash
# Minimal core binary
cargo build --release

# With S3 upload
cargo build --release --features upload-s3

# Everything: embedded extended tools + S3 + SFTP + SMB
cargo build --release --features "extended-tools,upload"
```

| Feature | Adds |
|---|---|
| `extended-tools` | Additional embedded Windows tooling |
| `memdump` | `winpmem.exe` memory acquisition (implies `extended-tools`) |
| `upload-s3` | S3 / S3-compatible upload (AWS SDK + Tokio) |
| `upload-sftp` | SFTP upload (libssh2) |
| `upload-smb` | *No effect*; SMB and folder upload are always compiled in |
| `upload` | All of the above |

> ⚠️ `default = []`: **a plain `cargo build --release` has no S3 and no SFTP support.** Add the features you need.

### Choosing the embedded config at build time

The build script copies `config/$CONFIG_FILE` into the binary, defaulting to `config.yml` (a Linux profile). This is how you bake a platform profile in:

```bash
CONFIG_FILE=config_linux.yml.template   cargo build --release
CONFIG_FILE=config_windows.yml.template cargo build --release --target x86_64-pc-windows-msvc
CONFIG_FILE=config_macos.yml.template   cargo build --release
```

The build fails immediately if the named file is missing.

### Build notes

- The `upload-s3` feature requires **rustc ≥ 1.91.1** (`rustup update stable`).
- The build script downloads the Sysinternals suite (and WinPmem under `extended-tools`/`memdump`), extracts the arch-correct binaries into `tools/`, and deletes the archive. **Network is not required**: download failures degrade to a warning, and the repository ships a populated `tools/`. Existing tools are never re-downloaded, and binaries of the wrong architecture are pruned automatically when you switch targets.
- **Cross-compiling to Windows from Linux requires mingw-w64 binutils** (`x86_64-w64-mingw32-windres` / `i686-w64-mingw32-windres`) on `PATH`; the build panics without it.
- Windows MSVC targets link with `-C target-feature=+crt-static`, producing an executable with no Visual C++ redistributable dependency. The embedded manifest requests `requireAdministrator`, so the binary always elevates.
- Supported target architectures are `x86_64` and `i686`.

---

## Documentation

Full documentation, covering deployment guides, configuration reference and parser internals, is available at **[aralez.co](https://aralez.co)**.

---

## Contributing & License

Pull requests for new parsers, artifact profiles and performance work are welcome.

- Describe the performance impact of collection-path changes in your PR.
- Open an **Issue** for bugs and feature requests.

Licensed under the [Apache-2.0 License](LICENSE).
