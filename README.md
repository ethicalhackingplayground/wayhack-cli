# WayHack CLI

🚀 **A powerful command-line interface for WayHack bug bounty automation**

WayHack CLI is a comprehensive security testing toolkit that bridges the gap between manual penetration testing and automated vulnerability discovery. Built from the ground up in Go, it provides seamless integration with popular security tools while connecting to WayHack's remote API service for command suggestions and enhanced workflow automation.

## 🌟 Key Features

### Core Capabilities
- **🔥 High Performance**: Written in Go with zero runtime dependencies - single binary deployment
- **🌍 Universal Compatibility**: Native support for Windows, Linux, and macOS with consistent behavior
- **🛠️ Tool Ecosystem Integration**: Direct execution and management of security tools
- **🔗 API Integration**: Command generation and suggestions via WayHack's remote API service
- **📊 Comprehensive Tracking**: Automatic capture and organization of all scan outputs with rich metadata

### Advanced Workflow Features
- **🎯 Interactive Command Selection**: Browse, filter, and execute API-generated commands with real-time feedback
- **📈 Scan History Management**: Complete audit trail of all security testing activities
- **🔍 Tool Discovery**: Automatic detection and verification of installed security tools
- **📁 Organized Output Storage**: Structured file system for scan results with searchable metadata

## 📦 Installation

### 🛠️ Build from Source

```bash
# Prerequisites: Go 1.21+
git clone https://github.com/ethicalhackingplayground/wayhack-cli.git
cd wayhack-cli

# Download dependencies
go mod download

# Build for your platform
go build -ldflags "-s -w" -o wayhack main.go
```

## ⚙️ Initial Setup

### 🔑 API Configuration

WayHack CLI requires API credentials to access the command generation service. Configure your credentials using:

```bash
# Interactive setup wizard
wayhack setup

# Follow the prompts:
# API URL: https://wayhack.sh (default)
# API Key: your_generated_api_key_here
```

## 📋 Available Commands

### 🔧 `wayhack setup`

Configure API credentials for the CLI:

```bash
wayhack setup
```

Guides you through:
1. Enter API URL (default: https://wayhack.sh)
2. Enter your API key
3. Verify connection and save configuration

### 🔍 `wayhack check`

Verify API configuration and check for installed security tools:

```bash
wayhack check
```

Checks for:
- API configuration validity
- Premium subscription status
- Installed tools: ffuf, dirsearch, nuclei, gobuster, httpx

### 📋 `wayhack list`

Display available tools from the API:

```bash
wayhack list
```

Shows all enabled tools and indicates whether each is installed on your system.

### 🔍 `wayhack search`

Search for URLs and endpoints using various sources:

```bash
# Basic domain search
wayhack search --domain example.com

# Search with specific sources
wayhack search --domain example.com --sources wayback,commoncrawl

# Include subdomains
wayhack search --domain example.com --include-subdomains

# Filter by file extensions
wayhack search --domain example.com --extensions php,asp,jsp

# Search specific path
wayhack search --domain example.com --path /admin

# Limit results
wayhack search --domain example.com --limit 100

# Save output to file
wayhack search --domain example.com --output results.txt

# Show only parameters
wayhack search --domain example.com --only-params

# Exclude certain extensions
wayhack search --domain example.com --exclude-extensions css,js,png

# Sort by uniqueness
wayhack search --domain example.com --sort-by-uniqueness

# Use proxies
wayhack search --domain example.com --proxies proxy1,proxy2

# Silent mode
wayhack search --domain example.com --silent
```

**Available Flags:**
- `--domain` (required): Target domain to search supports regex for an example (*.bmw.com)
- `--sources`: Comma-separated list of sources to use
- `--include-subdomains`: Include subdomains in search
- `--extensions`: Comma-separated list of file extensions to include
- `--path`: Specific path to search for
- `--output`: Output file path
- `--limit`: Maximum number of results
- `--only-params`: Show only URLs with parameters
- `--exclude-extensions`: Comma-separated list of extensions to exclude
- `--sort-by-uniqueness`: Sort results by uniqueness
- `--proxies`: Comma-separated list of proxies
- `--silent`: Run in silent mode

### 🛠️ `wayhack run`

Execute security tools directly with automatic output capture:

```bash
# Run a tool with arguments
wayhack run nuclei -u http://example.com -severity critical

# Run with complex arguments
wayhack run ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200
```

Features:
- Automatic output capture and organization
- Scan ID generation for result tracking
- Premium subscription verification
- Tool installation verification

### 🎯 `wayhack generate`

Generate API-suggested commands for security testing:

```bash
# Generate commands for a tool and target
wayhack generate nuclei http://example.com

# Filter by category
wayhack generate --category web nuclei http://example.com

# Interactive mode for command selection
wayhack generate --interactive nuclei http://example.com
```

**Available Flags:**
- `--category`: Filter commands by category
- `--interactive`: Enable interactive command selection mode

### 📊 `wayhack view`

View scan results and history:

```bash
# List all scans
wayhack view

# View latest scan
wayhack view --latest

# View specific number of recent scans
wayhack view --count 10

# Filter by tool
wayhack view --tool nuclei

# View detailed information
wayhack view --detailed

# View scan statistics
wayhack view --stats

# Generate HTML report
wayhack view --report html

# Generate PDF report
wayhack view --report pdf

# View specific scan by ID
wayhack view scan_id_here
```

**Available Flags:**
- `--latest`: Show most recent scan
- `--count`: Number of recent scans to show
- `--tool`: Filter by specific tool
- `--detailed`: Show detailed scan information
- `--stats`: Show scan statistics
- `--report`: Generate report (html/pdf)

### 🎧 `wayhack listen`

Run in background mode to poll for and execute commands:

```bash
# Start listening for commands
wayhack listen

# Listen with custom polling interval (default: 30 seconds)
wayhack listen --interval 60
```

Features:
- Polls server every 30 seconds (configurable)
- Executes commands in background
- 5-hour runtime limit
- Automatic premium subscription verification

### ℹ️ `wayhack version`

Display version and system information:

```bash
wayhack version
```

Shows:
- CLI version
- Go version
- Platform information
- Build details

### ❓ `wayhack help`

Display help information:

```bash
# General help
wayhack help

# Command-specific help
wayhack help search
wayhack help generate
```

## 🔧 Configuration

WayHack CLI stores configuration in:
- **Linux/macOS**: `~/.wayhack-config.json`
- **Windows**: `%USERPROFILE%\.wayhack-config.json`

Configuration includes:
- API URL and credentials
- Output directory settings
- Tool preferences

## 🛠️ Supported Tools

The CLI integrates with common security tools:
- **ffuf**: Fast web fuzzer
- **dirsearch**: Directory scanner
- **nuclei**: Vulnerability scanner
- **gobuster**: Directory/DNS brute-forcer
- **httpx**: HTTP toolkit

And supports execution of any command-line security tool installed on your system.

## 📝 Examples

### Basic Workflow

```bash
# 1. Setup API credentials
wayhack setup

# 2. Check system and tools
wayhack check

# 3. List available tools
wayhack list

# 4. Search for URLs
wayhack search --domain example.com --include-subdomains

# 5. Generate commands for testing
wayhack generate nuclei http://example.com

# 6. Run a security tool
wayhack run nuclei -u http://example.com -severity critical

# 7. View results
wayhack view --latest
```

### Advanced Usage

```bash
# Search with multiple filters
wayhack search --domain example.com --extensions php,asp --exclude-extensions css,js --limit 500

# Interactive command generation
wayhack generate --interactive --category web nuclei http://example.com

# Generate detailed reports
wayhack view --tool nuclei --report html

# Background monitoring
wayhack listen --interval 45
```

## 🔒 Security Notes

- API keys are stored securely in local configuration files
- All tool execution is performed locally on your system
- Scan results are stored locally unless explicitly shared
- Premium subscription required for CLI access

## 📞 Support

For issues, feature requests, or questions:
- GitHub Issues: [wayhack-cli/issues](https://github.com/ethicalhackingplayground/wayhack-cli/issues)
- Documentation: [wayhack.sh/docs](https://docs.wayhack.sh)
- Community: [discord](https://discord.gg/HyjK4eUQAp)
- Email: [support@wayhack.sh](mailto:support@wayhack.sh)