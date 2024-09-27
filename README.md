# Aralez
<p align="center">
  <img src="./assets/logo.png" alt="Aralez Logo" width="256" height="256"/>
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![](https://img.shields.io/badge/build-passing-brightgreen)

Aralez is a triage collector tool designed for gathering critical system information and files from a Windows machine. It automates the process of collecting data from various system tools, gathering network and process information, and retrieving files from an NTFS file system.

> **Note**: `aralez.exe` can only be executed on Windows and requires administrative privileges.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output](#output)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🤖 **Automated Tool Execution**: Runs a predefined set of tools to collect system data.
- 🌐 **Network and Process Information Gathering**: Collects detailed network and process information.
- 🛠️ **Change Configuration Directly with Your Binary**: Generate a new binary with an updated configuration file directly using your current Aralez executable. This feature allows you to modify the embedded configuration without the need to recompile the source code. Simply specify the new configuration file and the desired output name for the executable, and Aralez will create a new version tailored to your updated settings.
- 📁 **NTFS File Retrieval**: Retrieves files from the NTFS file system based on specific search configurations.
- 🗜️ **Data Compression**: Compresses the collected data into a ZIP archive for easy transport and analysis.
- 🔒 **Encryption Support**: Supports file encryption using AES-GCM with a customizable password.

## Installation

### Prerequisites

- **Windows OS**: `aralez.exe` is designed to run on Windows systems.
- **Administrative Privileges**: The tool must be executed with administrative rights.

### Build Instructions

#### Windows
> [!IMPORTANT] 
> To be compatible with Windows 7, you should compile on Windows. If you want to build `aralez.exe` from the source:

1. **Rust**: Ensure you have the Rust toolchain installed. You can install Rust by following the instructions at [rust-lang.org](https://www.rust-lang.org/).
   
2. **Clone the repository**:
   ```bash
   git clone https://github.com/abaghinyan/aralez.git
   cd aralez
   ```

3. **Build the project**:
   ```bash
   cargo build --release
   ```

4. **The executable**: The `aralez.exe` binary will be located in the `target/release` directory.

#### Linux (Ubuntu)
> [!WARNING] 
> On Linux, you cannot compile using the `i686-pc-windows-msvc` or `x86_64-pc-windows-msvc` targets, meaning your binary will not be compatible with Windows 7 if you attempt to use these targets.

1. **Install Required Packages**
Install the necessary tools for cross-compiling to Windows using `mingw-w64`:
    ```bash
    sudo apt install mingw-w64
    ```

2. **Rust**: Ensure you have the Rust toolchain installed. You can install Rust by following the instructions at [rust-lang.org](https://www.rust-lang.org/).
Add `i686-pc-windows-gnu` and `x86_64-pc-windows-gnu`
    ```bash
    rustup target add i686-pc-windows-gnu
    rustup target add x86_64-pc-windows-gnu
    ```
3. **Clone the repository**:
   ```bash
   git clone https://github.com/abaghinyan/aralez.git
   cd aralez
   ```
4. **Build the project**:
Compile the project for the Windows GNU targets:
   ```bash
   cargo build --release --target i686-pc-windows-gnu
   cargo build --release --target x86_64-pc-windows-gnu
   ```

5. **The executable**: 
The `aralez.exe` binary will be located in the `target/i686-pc-windows-gnu/release` and `target/x86_64-pc-windows-gnu/release` directories.

## Usage

### Basic Command

Run the tool with the following command:
```bash
aralez.exe [OPTIONS]
```

### Options

- `--debug`: Activates debug mode, providing more verbose output.
- `--show_config`: Displays the current configuration in a pretty-printed YAML format.
- `--change_config CONFIG_FILE --output OUTPUT_FILE`: Updates the embedded configuration using CONFIG_FILE and outputs the modified executable to OUTPUT_FILE.

### Example
To update the embedded configuration and specify the output executable:

```bash
aralez.exe --change_config new_config.yml --output new_aralez.exe
```
This will create a new aralez with a new config file.

Activate debug mode and start the data collection process.
```bash
aralez.exe --debug
```

## Configuration

### Embedded Configuration

Aralez uses an embedded YAML configuration file to define the directories, objects (file or directory), and other parameters for file retrieval. This configuration is expanded for each user detected on the system.

### Search Configurations

Each search configuration specifies:

- `dir_path`: The directory to search within.
- `objects`: A list of objects to include.
- `max_size`: The maximum file size to retrieve.
- `encrypt`: An optional password for AES-GCM encryption. If provided, the files will be encrypted and saved with an `.enc` extension.
- `regex`: Activate the regex in objects 

#### Windows Environment Variables for dir_path

Aralez supports the inclusion of Windows environment variables within the `dir_path` field, allowing dynamic file retrieval based on system-specific paths. Variables must be wrapped in %...% and will automatically expand to the corresponding system values during execution. For example, `%USERPROFILE%` will be replaced by the user's profile directory. This feature provides flexibility when defining file retrieval paths, making it easier to target system-specific locations across different machines and users.

**Example of dir_path with environment variables**
```yml
entries:
  files:
    - dir_path: "%USERPROFILE%\\Documents"
      objects: [".docx", ".pdf"]
      max_size: 1048576
      encrypt: "infected"
```

#### Regex Patterns for objects

Aralez allows you to define complex file search patterns using regular expressions (regex) **for objects only**, not for directory paths. You can use these patterns to retrieve files based on their extension or location within the directory tree.

- `[".*\\.evtx$"]`: This pattern will match files with a `.evtx` extension located in **one level** of subdirectories. Specifically:
  - `.*`: Matches any file name without extension.
  - `\\.`: Matche dot.
  - `evtx$`: Matches any file ending with the `evtx` extension.

- `[".*\\\\.*\\.evtx$"]`: This pattern will match `.evtx` files located in a folder **or any of its subfolders**. It works recursively:
  - `.*`: Matches any folder or subfolder (including recursive subdirectories).
  - `\\\\`: A literal backslash, separating the folder from the file name.
  - `*.evtx`: Matches any file ending with the `.evtx` extension.

> **Note**: if the objects end by `\\\\` it means that the **objects** are folders. If not, it means that we want to search files.

### Example Configuration
Collect some files:
```yaml
entries:
  files:
    - dir_path: "Users/{user}/Documents"
      objects: [".docx", ".pdf"]
      max_size: 1048576
      encrypt: "infected"
```
Execute Powershell command and save the output.
```yaml
entries:
  win_tools:
   - name: "powershell"
      args: ["-command", "Get-ComputerInfo"]
      output_file: "ComputerInfo.txt"
```

### Usage in Code

The tool uses the `SearchConfig` struct to manage and apply these configurations:

```rust
let config = SearchConfig {
    dir_path: "Users/{user}/Documents".to_string(),
    objects: Some(vec![".docx".to_string(), ".pdf".to_string()]),
    max_size: Some(1_048_576), // 1 MB
    encrypt: Some("infected".to_string()), // Encrypt files with the password "infected"
};
```

### Customizing the ZIP Archive Filename

You can customize the output ZIP filename by specifying the output_filename field in the configuration file. The tool supports the use of variables such as {{hostname}} to dynamically insert the machine's hostname, and {{datetime}} to insert the execution timestamp (in YYYY-MM-DD_HH-mm-ss format).
Example configuration:

```yaml
output_filename: "Aralez_{{hostname}}_{{datetime}}"
```

In this example, the output filename will be generated dynamically based on the machine’s hostname and the execution date. For instance, if the tool is run on a machine named MyPC on September 23, 2024, the output file will be named:

```python
Aralez_MyPC_2024-09-23_10-30-10.zip
```

This feature allows for easier identification and organization of collected data by machine and execution time.

## Encryption Process

### Overview

This application supports optional encryption of files using the AES-GCM (Galois/Counter Mode) algorithm. If the `encrypt` field in the configuration is set with a specific password, all files matching the specified criteria will be encrypted. Encrypted files are easily identifiable by the `.enc` extension appended to their original file names.

### How Encryption Works

1. **AES-GCM Encryption**:
   - The application uses the AES-GCM encryption algorithm, which is a symmetric key encryption method. It ensures both data confidentiality and integrity.
   - The provided password is hashed using SHA-256 to produce a 32-byte encryption key suitable for AES-256-GCM.

2. **File Naming**:
   - Encrypted files have the `.enc` extension added to their original file name. For example:
     - `logfile.txt` becomes `logfile.txt.enc`.
     - `report` becomes `report.enc`.

3. **Output**:
   - The encrypted file is written to the specified output directory with the `.enc` extension. The nonce used during encryption is stored in the file alongside the encrypted content.

### Decrypting Encrypted Files

To decrypt a file that was encrypted by this application, you will need:

1. **Original Password**: 
   - The same password that was used during the encryption process.

2. **Nonce**:
   - The nonce is automatically included in the encrypted file, so you do not need to provide it separately.

### Decryption Using Existing Tools

#### On Windows

To decrypt files on Windows, you can use the popular **OpenSSL** tool, which is available for Windows.

1. **Install OpenSSL**: If you don't already have OpenSSL installed, you can download it from [https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html).

2. **Decrypting a File**:
   - Use the following command in the Command Prompt (assuming `openssl` is in your PATH):
     ```cmd
     openssl enc -d -aes-256-gcm -in encrypted_file.enc -out decrypted_file.txt -k your_password -p -md sha256
     ```
   - Replace `encrypted_file.enc` with your actual encrypted file, `decrypted_file.txt` with the desired output file name, and `your_password` with the original password used during encryption.

3. **Example**:
   - To decrypt `logfile.txt.enc` using the password `"my_secure_password"`:
     ```cmd
     openssl enc -d -aes-256-gcm -in logfile.txt.enc -out logfile.txt -k my_secure_password -p -md sha256
     ```

#### On Linux

On Linux, **OpenSSL** is typically pre-installed on most distributions, so you can use it to decrypt files.

1. **Decrypting a File**:
   - Use the following command in the terminal:
     ```bash
     openssl enc -d -aes-256-gcm -in encrypted_file.enc -out decrypted_file.txt -k your_password -p -md sha256
     ```
   - Replace `encrypted_file.enc` with your actual encrypted file, `decrypted_file.txt` with the desired output file name, and `your_password` with the original password used during encryption.

2. **Example**:
   - To decrypt `logfile.txt.enc` using the password `"my_secure_password"`:
     ```bash
     openssl enc -d -aes-256-gcm -in logfile.txt.enc -out logfile.txt -k my_secure_password -p -md sha256
     ```

### Important Notes

- **Password Sensitivity**: 
  - Ensure the password used for encryption is stored securely and not shared in an insecure manner. If the password is lost, the encrypted data cannot be recovered.

- **Integrity**:
  - AES-GCM also provides integrity verification. If the file is tampered with, decryption will fail.

## Output

### Directory Structure

The collected data is saved in a directory named after the machine's hostname. This directory is compressed into a ZIP archive after the collection is complete.

### Output Files

- **System Tools**: Outputs from various system tools (e.g., `netstat`, `ipconfig`) are saved as text files.
- **NTFS Files**: Retrieved files are saved based on the configuration. If encryption is enabled, they are saved with an `.enc` extension.
- **Network and Process Information**: Collected network and process information is saved as separate text files.

### Example Output

```
machine_name/
├── C/
│   ├── Windows/
│   ├── Users/
│   ├── ProgramData
│   ├── $Recycle.Bin
│   ├── $MFT
├── tools/
│   ├── Autorunsc.txt
│   ├── Handle.txt
│   ├── TCPvCon.txt
│   ├── PSList.txt
│   ├── ListDLLs.txt
│   ├── PSService.txt
│   ├── NetStat.txt
│   ├── IPConfig.txt
│   ├── DNSCache.txt
│   ├── SystemInfo.txt
│   ├── TaskList.csv
│   ├── NetShare.csv
│   ├── ProcInfo.txt
│   ├── ProcDetailsInfo.txt
│   └── PortsInfo.txt
├── aralez.log
```

### Logfile: aralez.log

During the execution of the tool, all actions are logged into the `aralez.log` file. This log contains timestamps and detailed information about each step of the collection process, including tool execution status, errors, and other runtime information.

## Contributing

We welcome contributions to Aralez! Please submit pull requests with clear descriptions of your changes, or open issues to discuss any improvements or bugs you encounter.

## License

Aralez is open-source software licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.

