# 🚀 WayHack CLI

<div align="center">

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/ethicalhackingplayground/wayhack-cli/releases)
[![GitHub Release](https://img.shields.io/github/v/release/ethicalhackingplayground/wayhack-cli?style=for-the-badge)](https://github.com/ethicalhackingplayground/wayhack-cli/releases)

**A powerful, AI-enhanced command-line interface for bug bounty automation and reconnaissance**

[🔗 Website](https://wayhack.sh) • [📖 Documentation](https://wayhack.sh/docs) • [🐛 Report Bug](https://github.com/ethicalhackingplayground/wayhack-cli/issues) • [💡 Request Feature](https://github.com/ethicalhackingplayground/wayhack-cli/issues)

</div>

---

## 📋 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [📚 Usage Guide](#-usage-guide)
- [🛠️ Supported Tools](#️-supported-tools)
- [🔧 Development](#-development)
- [🤝 Contributing](#-contributing)
- [🐛 Troubleshooting](#-troubleshooting)
- [📄 License](#-license)

---

## 🎯 Overview

WayHack CLI is a next-generation command-line tool designed for bug bounty hunters and security researchers. Built with Go for maximum performance and portability, it seamlessly integrates with popular reconnaissance tools while providing AI-powered command generation and intelligent automation.

### 🌟 Why WayHack CLI?

- **🚀 Performance**: Written in Go with zero runtime dependencies
- **🤖 AI-Powered**: Intelligent command generation and optimization
- **🔄 Automation**: Streamline your bug bounty workflow
- **🌐 Cross-Platform**: Single binary for all major operating systems
- **🔧 Tool Integration**: Works with your existing security toolkit
- **📊 Real-time Monitoring**: Track command execution and results

---

## ✨ Features

### 🎯 Core Capabilities

| Feature | Description |
|---------|-------------|
| **🤖 AI Command Generation** | Generate optimized commands using advanced AI algorithms |
| **⚡ Direct Tool Execution** | Execute security tools directly through the CLI |
| **🔍 Interactive Mode** | Select and run commands with an intuitive interface |
| **📊 Tool Status Monitoring** | Real-time verification of installed tools |
| **🔄 Workflow Automation** | Chain multiple commands for complex reconnaissance |
| **📈 Progress Tracking** | Monitor command execution and results in real-time |

### 🛡️ Security & Performance

- **🔒 Secure API Communication**: Encrypted communication with WayHack platform
- **⚡ Lightning Fast**: Optimized Go implementation for maximum speed
- **💾 Memory Efficient**: Minimal resource usage even with large datasets
- **🔄 Concurrent Execution**: Run multiple tools simultaneously
- **📝 Comprehensive Logging**: Detailed execution logs for debugging

### 🌐 Platform Support

| Platform | Architecture | Status |
|----------|-------------|---------|
| **Windows** | x64 | ✅ Fully Supported |
| **Linux** | x64, ARM64 | ✅ Fully Supported |
| **macOS** | Intel, Apple Silicon | ✅ Fully Supported |

---

## 🚀 Quick Start

Get up and running in under 2 minutes:

```bash
# 1. Download and install
curl -sSL https://wayhack.sh/install.sh | bash

# 2. Configure your API key
wayhack setup

# 3. Check your tools
wayhack check

# 4. Start hunting!
wayhack generate ffuf https://example.com --interactive
```

---

## 📦 Installation

### 🎯 Method 1: Quick Install (Recommended)

**Linux/macOS:**
```bash
curl -sSL https://wayhack.sh/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr -useb https://wayhack.sh/install.ps1 | iex
```

### 🔗 Method 2: Direct Download

Download the latest release for your platform:

| Platform | Download Link |
|----------|---------------|
| **Windows x64** | [wayhack-windows-amd64.exe](https://wayhack.sh/api/cli/download?platform=win) |
| **Linux x64** | [wayhack-linux-amd64](https://wayhack.sh/api/cli/download?platform=linux) |
| **Linux ARM64** | [wayhack-linux-arm64](https://wayhack.sh/api/cli/download?platform=linux-arm) |
| **macOS Intel** | [wayhack-darwin-amd64](https://wayhack.sh/api/cli/download?platform=macos) |
| **macOS Apple Silicon** | [wayhack-darwin-arm64](https://wayhack.sh/api/cli/download?platform=macos-arm) |

### 🛠️ Method 3: Build from Source

```bash
# Clone the repository
git clone https://github.com/ethicalhackingplayground/wayhack-cli.git
cd wayhack-cli/cli

# Install dependencies
go mod download

# Build the binary
go build -o wayhack .

# Install globally (optional)
sudo mv wayhack /usr/local/bin/
```

### 📋 Post-Installation Setup

1. **Make executable** (Linux/macOS):
   ```bash
   chmod +x wayhack
   ```

2. **Add to PATH** (optional):
   ```bash
   sudo mv wayhack /usr/local/bin/
   ```

3. **Verify installation**:
   ```bash
   wayhack version
   ```

---

## ⚙️ Configuration

### 🔑 API Key Setup

1. **Get your API key** from [WayHack Settings](https://wayhack.sh/settings)
2. **Run the setup wizard**:
   ```bash
   wayhack setup
   ```
3. **Enter your credentials** when prompted

### 📁 Configuration File

Configuration is stored in `~/.wayhack-config.json`:

```json
{
  "apiUrl": "https://wayhack.sh",
  "apiKey": "wh_your_api_key_here",
  "preferences": {
    "interactive": true,
    "colorOutput": true,
    "maxConcurrent": 5,
    "timeout": 300
  }
}
```

### 🎛️ Environment Variables

You can also configure WayHack CLI using environment variables:

```bash
export WAYHACK_API_URL="https://wayhack.sh"
export WAYHACK_API_KEY="wh_your_api_key_here"
export WAYHACK_MAX_CONCURRENT="5"
export WAYHACK_TIMEOUT="300"
```

---

## 📚 Usage Guide

### 🔍 Basic Commands

```bash
# Display help
wayhack --help

# Show version information
wayhack version

# Check installed tools
wayhack check

# List available tools from API
wayhack list

# Configure API settings
wayhack setup
```

### 🎯 Tool Execution

#### Direct Execution
```bash
# Run ffuf with custom parameters
wayhack run ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt

# Execute nuclei vulnerability scan
wayhack run nuclei -u https://example.com -t /path/to/templates/

# Perform directory brute-force with gobuster
wayhack run gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# HTTP probing with httpx
wayhack run httpx -l domains.txt -o results.txt
```

#### Batch Execution
```bash
# Run multiple commands from file
wayhack batch commands.txt

# Execute with custom timeout
wayhack batch commands.txt --timeout 600
```

### 🤖 AI-Powered Command Generation

#### Basic Generation
```bash
# Generate commands for a specific tool
wayhack generate ffuf https://example.com

# Generate with specific category filter
wayhack generate nuclei https://example.com --category "Web Application"

# Generate multiple tool commands
wayhack generate --tools ffuf,nuclei,gobuster https://example.com
```

#### Interactive Mode
```bash
# Interactive command selection
wayhack generate ffuf https://example.com --interactive

# Interactive with preview
wayhack generate nuclei https://example.com --interactive --preview
```

#### Advanced Generation
```bash
# Generate with custom parameters
wayhack generate ffuf https://example.com \
  --wordlist /path/to/wordlist.txt \
  --threads 50 \
  --timeout 10

# Generate and save to file
wayhack generate gobuster https://example.com --output commands.txt

# Generate with specific techniques
wayhack generate nuclei https://example.com --techniques sqli,xss,rce
```

### 📊 Monitoring & Results

```bash
# Monitor running commands
wayhack status

# View command history
wayhack history

# Export results
wayhack export --format json --output results.json

# View detailed logs
wayhack logs --tail 100
```

---

## 🛠️ Supported Tools

WayHack CLI integrates with 50+ popular security tools:

### 🌐 Web Application Testing

| Tool | Category | Description |
|------|----------|-------------|
| **ffuf** | Fuzzing | Fast web fuzzer for directory/file discovery |
| **dirsearch** | Discovery | Advanced directory/file brute-forcer |
| **gobuster** | Discovery | Directory/DNS/vhost brute-forcer |
| **feroxbuster** | Discovery | Fast, simple, recursive content discovery |
| **wfuzz** | Fuzzing | Web application fuzzer |

### 🔍 Vulnerability Scanning

| Tool | Category | Description |
|------|----------|-------------|
| **nuclei** | Vulnerability | Fast and customizable vulnerability scanner |
| **nikto** | Web Scanner | Web server scanner |
| **sqlmap** | SQL Injection | Automatic SQL injection exploitation tool |
| **xsstrike** | XSS | Advanced XSS detection suite |
| **commix** | Command Injection | Command injection exploitation tool |

### 🌍 Network & Infrastructure

| Tool | Category | Description |
|------|----------|-------------|
| **nmap** | Port Scanning | Network discovery and security auditing |
| **masscan** | Port Scanning | High-speed port scanner |
| **httpx** | HTTP Probing | Fast HTTP toolkit |
| **subfinder** | Subdomain | Subdomain discovery tool |
| **amass** | OSINT | In-depth attack surface mapping |

### 📡 OSINT & Reconnaissance

| Tool | Category | Description |
|------|----------|-------------|
| **theHarvester** | OSINT | E-mail, subdomain, and people names harvester |
| **recon-ng** | Framework | Full-featured reconnaissance framework |
| **shodan** | Search Engine | Search engine for Internet-connected devices |
| **censys** | Search Engine | Search engine for Internet assets |
| **waybackurls** | Archive | Fetch URLs from Wayback Machine |

### 🔧 Utilities & Helpers

| Tool | Category | Description |
|------|----------|-------------|
| **curl** | HTTP Client | Command-line HTTP client |
| **wget** | Downloader | Network downloader |
| **jq** | JSON Parser | Command-line JSON processor |
| **grep** | Text Search | Pattern searching utility |
| **awk** | Text Processing | Pattern scanning and processing |

> **Note**: WayHack CLI can execute any command-line tool installed on your system, not just the ones listed above.

---

## 🔧 Development

### 🏗️ Building from Source

#### Prerequisites
- **Go 1.21+** - [Download Go](https://golang.org/dl/)
- **Git** - [Download Git](https://git-scm.com/downloads)

#### Build Process
```bash
# Clone repository
git clone https://github.com/ethicalhackingplayground/wayhack-cli.git
cd wayhack-cli/cli

# Download dependencies
go mod download

# Run tests
go test ./...

# Build for current platform
go build -o wayhack .

# Build for all platforms
./build.sh    # Linux/macOS
build.bat     # Windows
```

#### Cross-Platform Building
```bash
# Windows x64
GOOS=windows GOARCH=amd64 go build -o dist/wayhack-windows-amd64.exe .

# Linux x64
GOOS=linux GOARCH=amd64 go build -o dist/wayhack-linux-amd64 .

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o dist/wayhack-linux-arm64 .

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o dist/wayhack-darwin-amd64 .

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o dist/wayhack-darwin-arm64 .
```

### 📦 Dependencies

| Package | Purpose | License |
|---------|---------|---------|
| [cobra](https://github.com/spf13/cobra) | CLI framework | Apache 2.0 |
| [viper](https://github.com/spf13/viper) | Configuration management | MIT |
| [color](https://github.com/fatih/color) | Colored terminal output | MIT |
| [progressbar](https://github.com/schollz/progressbar) | Progress indicators | MIT |
| [tablewriter](https://github.com/olekukonko/tablewriter) | ASCII table generation | MIT |

### 🧪 Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test
go test -run TestCommandGeneration ./...

# Benchmark tests
go test -bench=. ./...
```

---

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### 🐛 Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating new issues
3. **Provide detailed information** including:
   - Operating system and version
   - WayHack CLI version
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages or logs

### 💡 Suggesting Features

1. **Check the roadmap** for planned features
2. **Use the feature request template**
3. **Describe the use case** and benefits
4. **Provide examples** of how it would work

### 🔧 Code Contributions

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Commit your changes**: `git commit -m 'Add amazing feature'`
7. **Push to the branch**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

### 📝 Coding Standards

- Follow Go best practices and conventions
- Use meaningful variable and function names
- Add comments for complex logic
- Ensure all tests pass
- Maintain backward compatibility when possible

---

## 🐛 Troubleshooting

### ❓ Common Issues

#### Tool Not Found
```bash
# Check if tool is installed
wayhack check

# Verify PATH configuration
echo $PATH

# Install missing tools
# Example for Ubuntu/Debian:
sudo apt update && sudo apt install ffuf nuclei gobuster
```

#### API Connection Issues
```bash
# Verify API credentials
wayhack setup

# Test connection
curl -H "Authorization: Bearer YOUR_API_KEY" https://wayhack.sh/api/health

# Check firewall/proxy settings
```

#### Permission Denied
```bash
# Make binary executable
chmod +x wayhack

# Check file permissions
ls -la wayhack

# Run with sudo if needed (not recommended)
sudo ./wayhack
```

#### Configuration Issues
```bash
# Reset configuration
rm ~/.wayhack-config.json
wayhack setup

# Verify configuration
cat ~/.wayhack-config.json

# Use environment variables as fallback
export WAYHACK_API_KEY="your_key_here"
```

### 🔍 Debug Mode

Enable debug mode for detailed logging:

```bash
# Enable debug output
wayhack --debug command

# Save debug logs to file
wayhack --debug command 2> debug.log

# Verbose output
wayhack --verbose command
```

### 📞 Getting Help

- **📖 Documentation**: [wayhack.sh/docs](https://wayhack.sh/docs)
- **💬 Discord**: [Join our community](https://discord.gg/wayhack)
- **🐛 Issues**: [GitHub Issues](https://github.com/ethicalhackingplayground/wayhack-cli/issues)
- **📧 Email**: support@wayhack.sh

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Ethical Hacking Playground

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

[🔗 Website](https://wayhack.sh) • [📖 Documentation](https://wayhack.sh/docs) • [💬 Discord](https://discord.gg/wayhack) • [🐦 Twitter](https://twitter.com/wayhack)

Made with ❤️ by the [Ethical Hacking Playground](https://github.com/ethicalhackingplayground) team

</div>