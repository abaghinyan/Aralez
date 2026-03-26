// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2025 Areg Baghinyan. All Rights Reserved.
//
// Author(s): Areg Baghinyan
//
// Stream mode: OutputTarget abstraction for zero-folder streaming compression.
// In stream mode, every reader writes directly into a ZipWriter or TarBuilder —
// no temp folders, no intermediate files.  Memory usage: one 4-8 KB buffer (ZIP)
// or per-file buffer (TAR, bounded by max_size config).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Cursor, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use zip::{write::FileOptions, ZipWriter};

/// Global interrupt flag — set by the Ctrl+C handler.
pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Global silent flag — suppresses all terminal output when set.
pub static SILENT: AtomicBool = AtomicBool::new(false);

/// Quick check for Ctrl+C.  Call this in tight loops to bail early.
pub fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

/// Check if silent mode is active.
pub fn is_silent() -> bool {
    SILENT.load(Ordering::Relaxed)
}

// ── ZIP state ──────────────────────────────────────────────────────────────

/// Internal state held behind the Mutex in stream mode (ZIP).
pub struct ZipState {
    pub writer: ZipWriter<BufWriter<File>>,
    pub options: FileOptions<'static, ()>,
    pub base_path: String,
}

// ── TAR state ──────────────────────────────────────────────────────────────

/// Internal state held behind the Mutex in stream mode (TAR).
pub struct TarState {
    pub builder: tar::Builder<zstd::Encoder<'static, BufWriter<File>>>,
    pub base_path: String,
}

// ── OutputTarget ───────────────────────────────────────────────────────────

/// Determines where collected artifacts are written.
pub enum OutputTarget {
    /// Normal mode – write files to a folder on disk (current behaviour).
    Folder,
    /// Stream mode (ZIP) – write directly into a zip archive.
    Zip(Mutex<ZipState>),
    /// Stream mode (TAR) – write directly into a tar.zst archive.
    Tar(Mutex<TarState>),
}

// ── Internal TAR flush state ───────────────────────────────────────────────

/// Holds the mutex guard + buffer for a single TAR entry being written.
pub struct TarFlushState<'a> {
    guard: MutexGuard<'a, TarState>,
    path: String,
    buffer: Vec<u8>,
}

// ── OutputWriter ───────────────────────────────────────────────────────────

/// A thin writer returned by `OutputTarget::create_*` methods.
/// Implements `Write` so callers can use `write_all()` transparently.
pub enum OutputWriter<'a> {
    File(File),
    Zip(MutexGuard<'a, ZipState>),
    /// TAR variant: buffers all data, writes the complete TAR entry on flush().
    TarBuffer {
        state: Option<TarFlushState<'a>>,
    },
}

impl<'a> Write for OutputWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            OutputWriter::File(f) => f.write(buf),
            OutputWriter::Zip(z) => z.writer.write(buf),
            OutputWriter::TarBuffer { state } => {
                if let Some(ref mut s) = state {
                    s.buffer.extend_from_slice(buf);
                }
                Ok(buf.len())
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutputWriter::File(f) => f.flush(),
            OutputWriter::Zip(z) => z.writer.flush(),
            OutputWriter::TarBuffer { state } => {
                // Write the buffered data as a complete TAR entry
                if let Some(s) = state.take() {
                    let data = s.buffer;
                    let mut guard = s.guard;
                    let mut header = tar::Header::new_gnu();
                    header.set_size(data.len() as u64);
                    header.set_mode(0o644);
                    header.set_cksum();
                    let path = s.path;
                    guard
                        .builder
                        .append_data(&mut header, &path, Cursor::new(&data))
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }
                Ok(())
            }
        }
    }
}

impl Drop for OutputWriter<'_> {
    fn drop(&mut self) {
        // Best-effort flush for TAR entries that weren't explicitly flushed.
        if let OutputWriter::TarBuffer { state } = self {
            if state.is_some() {
                let _ = self.flush();
            }
        }
    }
}

impl OutputWriter<'_> {
    /// Returns a reference to the underlying `File` (Folder mode only).
    /// Useful for setting timestamps via `set_file_handle_times`.
    pub fn as_file(&self) -> Option<&File> {
        match self {
            OutputWriter::File(f) => Some(f),
            _ => None,
        }
    }
}

// ── OutputTarget implementation ────────────────────────────────────────────

impl OutputTarget {
    /// `true` when operating in stream (zip or tar) mode.
    pub fn is_stream(&self) -> bool {
        !matches!(self, OutputTarget::Folder)
    }

    /// Helper to strip the root_output absolute path prefix so that
    /// archives contain relative paths (Windows Explorer rejects absolute paths).
    fn make_archive_path(base_path: &str, full_path: &str) -> String {
        let base_backslash = format!("{}\\", base_path);
        let base_slash = format!("{}/", base_path);
        
        let relative = full_path
            .strip_prefix(&base_backslash)
            .or_else(|| full_path.strip_prefix(&base_slash))
            .or_else(|| full_path.strip_prefix(base_path))
            .unwrap_or(full_path);
            
        // Strip any lingering leading separators and convert to standard slashes
        relative.trim_start_matches(|c| c == '\\' || c == '/').replace('\\', "/")
    }

    /// Create or overwrite a file entry.
    ///
    /// * **Folder mode** – creates parent directories + file on disk.
    /// * **Zip mode** – calls `start_file()` on the `ZipWriter`.
    /// * **Tar mode** – returns a buffer; entry is written on `flush()`.
    ///
    /// The returned `OutputWriter` implements `Write`.
    pub fn create_entry(&self, full_path: &str) -> io::Result<OutputWriter<'_>> {
        match self {
            OutputTarget::Folder => {
                if let Some(parent) = Path::new(full_path).parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = File::create(full_path)?;
                Ok(OutputWriter::File(file))
            }
            OutputTarget::Zip(mutex) => {
                let mut guard = mutex
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let zip_path = Self::make_archive_path(&guard.base_path, full_path);
                let opts = guard.options;
                guard.writer.start_file(&zip_path, opts)?;
                Ok(OutputWriter::Zip(guard))
            }
            OutputTarget::Tar(mutex) => {
                let guard = mutex
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let tar_path = Self::make_archive_path(&guard.base_path, full_path);
                Ok(OutputWriter::TarBuffer {
                    state: Some(TarFlushState {
                        guard,
                        path: tar_path,
                        buffer: Vec::new(),
                    }),
                })
            }
        }
    }

    /// Create a file entry, failing with `AlreadyExists` if it already exists
    /// on disk (Folder mode).  In Zip/Tar mode it always succeeds.
    pub fn create_new_entry(&self, full_path: &str) -> io::Result<OutputWriter<'_>> {
        match self {
            OutputTarget::Folder => {
                if let Some(parent) = Path::new(full_path).parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(full_path)?;
                Ok(OutputWriter::File(file))
            }
            OutputTarget::Zip(mutex) => {
                let mut guard = mutex
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let zip_path = Self::make_archive_path(&guard.base_path, full_path);
                let opts = guard.options;
                guard.writer.start_file(&zip_path, opts)?;
                Ok(OutputWriter::Zip(guard))
            }
            OutputTarget::Tar(mutex) => {
                let guard = mutex
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let tar_path = Self::make_archive_path(&guard.base_path, full_path);
                Ok(OutputWriter::TarBuffer {
                    state: Some(TarFlushState {
                        guard,
                        path: tar_path,
                        buffer: Vec::new(),
                    }),
                })
            }
        }
    }

    /// Copy a file from the filesystem into the output, streaming in 8 KB
    /// chunks.
    ///
    /// * **Folder mode** – `create_dir_all` + `fs::copy`.
    /// * **Zip mode** – opens source, `start_file()`, streams chunks.
    /// * **Tar mode** – reads source, appends as TAR entry.
    pub fn copy_file(&self, src: &Path, dest_path: &str) -> io::Result<()> {
        match self {
            OutputTarget::Folder => {
                if let Some(parent) = Path::new(dest_path).parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(src, dest_path)?;
                Ok(())
            }
            OutputTarget::Zip(mutex) => {
                let mut guard = mutex
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let zip_path = Self::make_archive_path(&guard.base_path, dest_path);
                let opts = guard.options;
                guard.writer.start_file(&zip_path, opts)?;
                let mut src_file = File::open(src)?;
                let mut buf = [0u8; 8192];
                loop {
                    let n = src_file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    guard.writer.write_all(&buf[..n])?;
                }
                Ok(())
            }
            OutputTarget::Tar(mutex) => {
                let mut guard = mutex
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let tar_path = Self::make_archive_path(&guard.base_path, dest_path);
                let meta = fs::metadata(src)?;
                let mut header = tar::Header::new_gnu();
                header.set_size(meta.len());
                header.set_mode(0o644);
                header.set_cksum();
                let mut src_file = File::open(src)?;
                guard
                    .builder
                    .append_data(&mut header, &tar_path, &mut src_file)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// Write raw bytes as a named entry.
    pub fn write_bytes(&self, full_path: &str, data: &[u8]) -> io::Result<()> {
        match self {
            OutputTarget::Tar(mutex) => {
                // For TAR, write directly without buffering
                let mut guard = mutex
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let tar_path = Self::make_archive_path(&guard.base_path, full_path);
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                guard
                    .builder
                    .append_data(&mut header, &tar_path, data)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(())
            }
            _ => {
                let mut w = self.create_entry(full_path)?;
                w.write_all(data)?;
                w.flush()?;
                Ok(())
            }
        }
    }

    /// Ensure a directory exists (Folder mode only; zip/tar ignores).
    pub fn ensure_dir(&self, path: &str) -> io::Result<()> {
        if let OutputTarget::Folder = self {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    /// Finalize the archive (stream mode only).
    pub fn finish(self) -> io::Result<()> {
        match self {
            OutputTarget::Zip(mutex) => {
                let state = mutex
                    .into_inner()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                state.writer.finish()?;
                Ok(())
            }
            OutputTarget::Tar(mutex) => {
                let state = mutex
                    .into_inner()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let encoder = state.builder.into_inner()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                encoder.finish()?;
                Ok(())
            }
            OutputTarget::Folder => Ok(()),
        }
    }
}
