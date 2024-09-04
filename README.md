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

- **Automated Tool Execution**: Runs a predefined set of tools to collect system data.
- **Network and Process Information Gathering**: Collects detailed network and process information.
- - **Change Configuration Directly with Your Binary**: Generate a new binary with an updated configuration file directly using your current Aralez executable. This feature allows you to modify the embedded configuration without the need to recompile the source code. Simply specify the new configuration file and the desired output name for the executable, and Aralez will create a new version tailored to your updated settings.
- **NTFS File Retrieval**: Retrieves files from the NTFS file system based on specific search configurations.
- **Data Compression**: Compresses the collected data into a ZIP archive for easy transport and analysis.
- **Encryption Support**: Supports file encryption using AES-GCM with a customizable password.

## Installation

### Prerequisites

- **Windows OS**: `aralez.exe` is designed to run on Windows systems.
- **Administrative Privileges**: The tool must be executed with administrative rights.

### Build Instructions

To be compatible with Windows 7, you should compile on Windows. If you want to build `aralez.exe` from the source:

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

Aralez uses an embedded YAML configuration file to define the directories, file extensions, and other parameters for file retrieval. This configuration is expanded for each user detected on the system.

### Search Configurations

Each search configuration specifies:

- `dir_path`: The directory to search within.
- `extensions`: A list of file extensions to include.
- `max_size`: The maximum file size to retrieve.
- `encrypt`: An optional password for AES-GCM encryption. If provided, the files will be encrypted and saved with an `.enc` extension.

### Example Configuration
Collect some files:
```yaml
entries:
  files:
    - dir_path: "Users/{user}/Documents"
      extensions: [".docx", ".pdf"]
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
    extensions: Some(vec![".docx".to_string(), ".pdf".to_string()]),
    max_size: Some(1_048_576), // 1 MB
    encrypt: Some("infected".to_string()), // Encrypt files with the password "infected"
};
```

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
│   ├── autorunsc.txt
│   ├── handle.txt
│   ├── tcpvcon.txt
│   ├── pslist.txt
│   ├── listdlls.txt
│   ├── psservice.txt
│   ├── netstat.txt
│   ├── ipconfig.txt
│   ├── dnscache.txt
│   ├── systeminfo.txt
│   ├── tasklist.csv
│   ├── netshare.csv
│   ├── ps_info.txt
│   ├── ps_details_info.txt
│   └── ports_info.txt
```

## Contributing

We welcome contributions to Aralez! Please submit pull requests with clear descriptions of your changes, or open issues to discuss any improvements or bugs you encounter.

## License

Aralez is open-source software licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.

