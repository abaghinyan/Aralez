# Aralez
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
> * On **Windows**, use `aralez_x64.exe` or `aralez_x86.exe` (requires administrative privileges).
> * On **Linux**, use the `aralez` binary (requires root privileges).

---

## ✨ Features at a Glance

* 🔍 **Cross-Platform Support** - Collect forensic data on both Windows and Linux systems.
* ⚡ **Automated Data Collection** - Extracts information from NTFS/ext file systems, system logs, and critical artifacts.
* 🛠️ **Integrated Tool Support** - Leverages internal, external, and system tools for comprehensive analysis.
* 🔐 **Secure by Design** - Uses AES-GCM encryption to protect sensitive data from accidental propagation.
* ⚙️ **Customizable Configurations** - Update the embedded YAML configuration directly or via a new binary.

---

## 🚀 Quick Start

1. **Download**
   Clone the repository or grab a precompiled binary:

   * **Windows (64-bit):** `aralez_x64.exe`
   * **Windows (32-bit):** `aralez_x86.exe`
   * **Linux (x86\_64):** `aralez`

2. **Execute**

   * On Windows: Run the appropriate `.exe` as **Administrator**
   * On Linux: Run:

     ```bash
     sudo ./aralez
     ```

3. **Review Outputs**
   Collected data and logs are saved in a structured format, ready for forensic analysis.

---

## 📖 Documentation

Comprehensive documentation - including configuration guides, usage examples, and tool descriptions - is available on the [official website](https://aralez.co).

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
