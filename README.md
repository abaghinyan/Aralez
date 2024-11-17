# Aralez
<p align="center">
  <img src="./assets/logo.png" alt="Aralez Logo" width="256" height="256"/>
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![](https://img.shields.io/badge/build-passing-brightgreen)

Aralez is an advanced Windows triage collection tool designed to streamline the process of gathering critical forensic data. Built with flexibility and automation in mind, it simplifies data collection for incident response and forensic investigations.

> **Note**: `aralez.exe` can only be executed on Windows and requires administrative privileges.

## Features

- **Automated Data Collection**: Collects data from NTFS file systems, system logs, and critical artifacts with predefined configurations.
- **Integrated Tool Support**: Supports internal, external, and system tools for comprehensive analysis.
- **Encryption for Safety**: Ensures sensitive data is encrypted using AES-GCM to protect it from accidental propagation.
- **Customizable Configurations**: Modify and update the embedded YAML configuration directly or through a new binary.
- **Output Compression**: Compresses collected data into ZIP archives for easy handling.

## Quick Start

1. **Download**: Clone the repository or download the precompiled binary.
2. **Execute**: Run `aralez.exe` with administrative privileges on a Windows machine.
3. **Review Outputs**: Collected data and logs are stored in a structured format for easy analysis.

## Documentation

Detailed documentation, including configuration guides, usage examples, and tool descriptions, is available on the [official website](https://aralez.co).

## Contributing

We welcome contributions to Aralez! Please submit pull requests with clear descriptions of your changes, or open issues to discuss any improvements or bugs you encounter.

## License

Aralez is open-source software licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.

