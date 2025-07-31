# WayHack CLI (Go Version)

A powerful command-line interface for WayHack bug bounty automation, now written in Go for better performance and easier distribution.

## Features

- **Fast and Lightweight**: Written in Go, no runtime dependencies
- **Cross-Platform**: Single binary for Windows, Linux, and macOS
- **Tool Integration**: Direct execution of bug bounty tools (ffuf, nuclei, gobuster, etc.)
- **Command Generation**: AI-powered command suggestions from WayHack API
- **Interactive Mode**: Select and run commands interactively
- **Tool Status Checking**: Verify which tools are installed on your system
- **Output Tracking**: Automatically saves all tool outputs with metadata for later review
- **Scan Management**: View and manage previous scan results with filtering options

## Installation

### Quick Install (Recommended)

Download the pre-built binary for your platform:

- **Windows**: [wayhack-windows-amd64.exe](https://wayhack.sh/api/cli/download?platform=win)
- **Linux**: [wayhack-linux-amd64](https://wayhack.sh/api/cli/download?platform=linux)
- **macOS Intel**: [wayhack-darwin-amd64](https://wayhack.sh/api/cli/download?platform=macos)
- **macOS Apple Silicon**: [wayhack-darwin-arm64](https://wayhack.sh/api/cli/download?platform=macos-arm)

### Manual Installation

1. Download the appropriate binary for your platform
2. Make it executable (Linux/macOS): `chmod +x wayhack-*`
3. Move to your PATH: `mv wayhack-* /usr/local/bin/wayhack`
4. Run setup: `wayhack setup`

### Build from Source

```bash
git clone https://github.com/ethicalhackingplayground/wayhack-cli.git
cd wayhack-cli
go mod download
go build -o wayhack main.go
```

## Setup

1. Get your API key from [WayHack Settings](https://wayhack.sh/settings)
2. Run the setup command:
   ```bash
   wayhack setup
   ```
3. Enter your API URL and key when prompted

## Usage

### Basic Commands

```bash
# Check which tools are installed
wayhack check

# List available tools from API
wayhack list

# View scan results and history
wayhack view

# Show version information
wayhack version
```

### Direct Tool Execution

```bash
# Run ffuf with custom parameters
wayhack run ffuf -u http://example.com/FUZZ -w wordlist.txt

# Run nuclei scan
wayhack run nuclei -u http://example.com -t templates/

# Run gobuster directory scan
wayhack run gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
```

### Command Generation

```bash
# Generate commands for a tool and URL
wayhack generate ffuf http://example.com

# Interactive mode - select and run commands
wayhack generate nuclei http://example.com --interactive

# Filter by category
wayhack generate dirsearch http://example.com --category "Web Application"
```

### View Scan Results

All tool executions are automatically tracked and saved. Use the `view` command to access previous scan results:

```bash
# List all previous scans
wayhack view

# View a specific scan by ID
wayhack view scan_20240101_120000_nmap

# View the latest scan
wayhack view --latest

# View the last 5 scans
wayhack view --count 5

# View latest scan from a specific tool
wayhack view --tool nuclei --latest

# View last 10 scans from a specific tool
wayhack view --tool ffuf --count 10
```

#### Scan Output Structure

Each scan creates a unique directory with the following structure:
```
~/.wayhack/outputs/
├── scan_20240101_120000_nmap/
│   ├── stdout.txt          # Tool output
│   ├── stderr.txt          # Error output
│   └── metadata.json      # Scan metadata
├── scan_20240101_130000_nuclei/
│   ├── stdout.txt
│   ├── stderr.txt
│   └── metadata.json
└── scans.json             # Global scan index
```

#### Scan Metadata

Each scan includes detailed metadata:
- **Scan ID**: Unique identifier with timestamp
- **Tool**: Security tool used
- **Command**: Full command executed
- **Target**: Target URL or IP
- **Timestamp**: When the scan was executed
- **Duration**: How long the scan took
- **Status**: Success or failure
- **Exit Code**: Tool exit code

## Supported Tools

The CLI can execute and generate commands for:

- **ffuf** - Fast web fuzzer
- **dirsearch** - Directory/file brute-forcer
- **nuclei** - Vulnerability scanner
- **gobuster** - Directory/DNS/vhost brute-forcer
- **httpx** - HTTP toolkit
- And any other command-line tool installed on your system

## Building

### Prerequisites

- Go 1.21 or later

### Build Commands

```bash
# Build for current platform
go build -o wayhack .

# Build for all platforms
./build.sh    # Linux/macOS
build.bat     # Windows
```

### Cross-Platform Build

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o wayhack-windows.exe .

# Linux
GOOS=linux GOARCH=amd64 go build -o wayhack-linux .

# macOS
GOOS=darwin GOARCH=amd64 go build -o wayhack-macos .
```

## Configuration

Configuration is stored in `~/.wayhack-config.json`:

```json
{
  "apiUrl": "https://wayhack.sh",
  "apiKey": "wh_your_api_key_here"
}
```

## Dependencies

- [cobra](https://github.com/spf13/cobra) - CLI framework
- [color](https://github.com/fatih/color) - Colored terminal output
- [term](https://golang.org/x/term) - Terminal utilities

## Migration from JavaScript Version

The Go version maintains full compatibility with the JavaScript version:

- Same command structure and arguments
- Same configuration file format
- Same API endpoints and authentication
- Improved performance and reliability
- No Node.js dependency required

## Troubleshooting

### Tool Not Found
Ensure the tool is installed and available in your PATH:
```bash
wayhack check  # Verify tool installation
```

### API Connection Issues
Verify your API credentials:
```bash
wayhack setup  # Reconfigure API settings
```

### Permission Denied
Make the binary executable:
```bash
chmod +x wayhack
```

### Output Directory Issues
If you encounter issues with scan output storage:
```bash
# Check output directory permissions
ls -la ~/.wayhack/outputs/

# Manually create output directory if needed
mkdir -p ~/.wayhack/outputs/
```

### View Command Not Showing Scans
If the view command shows no scans:
- Ensure you've run at least one scan using `wayhack run` or `wayhack generate`
- Check that the output directory exists: `~/.wayhack/outputs/`
- Verify scan metadata file exists: `~/.wayhack/outputs/scans.json`

### Scan Output Corruption
If scan outputs appear corrupted:
- Check disk space availability
- Ensure proper file permissions in the output directory
- Try running a new scan to verify the issue persists

## License

MIT License - see LICENSE file for details.