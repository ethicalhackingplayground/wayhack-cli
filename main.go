package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	Version        = "2.0.0"
	ConfigFileName = ".wayhack-config.json"
	OutputsDir     = ".wayhack-outputs"
	MetadataFile   = "metadata.json"
)

type Config struct {
	APIUrl string `json:"apiUrl"`
	APIKey string `json:"apiKey"`
}

type ScanMetadata struct {
	ID        string    `json:"id"`
	Tool      string    `json:"tool"`
	Command   string    `json:"command"`
	Target    string    `json:"target"`
	Timestamp time.Time `json:"timestamp"`
	Duration  string    `json:"duration"`
	Status    string    `json:"status"`
	OutputDir string    `json:"outputDir"`
	ExitCode  int       `json:"exitCode"`
}

type Tool struct {
	Name    string `json:"name"`
	Install string `json:"install"`
}

type Command struct {
	Description string `json:"description"`
	Category    string `json:"category"`
	Command     string `json:"command"`
}

type GenerateResponse struct {
	Commands []Command `json:"commands"`
}

type EnabledToolsResponse struct {
	Tools []string `json:"tools"`
}

type SubscriptionPlan struct {
	Plan             string `json:"plan"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
	SearchesPerMonth int    `json:"searchesPerMonth"`
	Active           bool   `json:"active"`
}

type SubscriptionResponse struct {
	HasCLIAccess  bool              `json:"hasCLIAccess"`
	Subscriptions *SubscriptionPlan `json:"subscriptions"`
}

var (
	// Colors
	blue   = color.New(color.FgBlue).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	gray   = color.New(color.FgHiBlack).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	white  = color.New(color.FgWhite).SprintFunc()

	// Global config
	config Config
)

func main() {
	var rootCmd = &cobra.Command{
		Use:     "wayhack",
		Short:   "WayHack CLI - Bug bounty automation tool",
		Version: Version,
		Long: `WayHack CLI - Bug bounty automation tool

Examples:
  wayhack setup                                    Configure API key
  wayhack list                                     Show available tools
  wayhack check                                    Check tool installations
  wayhack version                                  Show version info

URL Discovery & Search:
  wayhack search --domain example.com              Basic domain search
  wayhack search --domain example.com --sources wayback,crtsh
  wayhack search --domain example.com --include-subdomains
  wayhack search --domain example.com --extensions pdf,doc,xls
  wayhack search --domain example.com --path "/admin"

Direct Tool Execution:
  wayhack run ffuf -u http://example.com/FUZZ -w wordlist.txt
  wayhack run nuclei -u http://example.com -t templates/
  wayhack run gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt

Complex Commands (with quotes and special characters):
  wayhack run ffuf -u "http://example.com/FUZZ" -w wordlist.txt -H "User-Agent: Mozilla/5.0"
  wayhack run curl -H "Authorization: Bearer token" "http://api.example.com/data"
  wayhack run nuclei -u http://example.com -severity critical,high -o results.txt

Command Generation:
  wayhack generate ffuf http://example.com         Generate commands
  wayhack generate nuclei http://example.com -c "Web Application"
  wayhack generate dirsearch http://example.com --interactive

View Scan Results:
  wayhack view                                     List all scans
  wayhack view scan_1234567890                     View specific scan output
  wayhack view --latest                            View latest scan
  wayhack view --latest --tool ffuf               View latest ffuf scan
  wayhack view --count 10                          View last 10 scans
  wayhack view --detailed                          List scans with detailed information

Note: 
  - Use 'wayhack search' to discover URLs and perform OSINT reconnaissance
  - Use 'wayhack run' to execute tools directly with their full arguments
  - Use 'wayhack generate' to get API-suggested commands from the service
  - Use 'wayhack view' to see saved outputs from previous scans
  - Complex arguments with spaces or special characters are properly handled
  - Quotes in commands are preserved and passed correctly to tools
  - All tool outputs are automatically saved and can be viewed later`,
	}

	// Load config
	loadConfig()

	// Add commands
	rootCmd.AddCommand(setupCmd())
	rootCmd.AddCommand(checkCmd())
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(generateCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(listenCmd())
	rootCmd.AddCommand(searchCmd())
	rootCmd.AddCommand(viewCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s Error: %v\n", red("❌"), err)
		os.Exit(1)
	}
}

func setupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Setup WayHack CLI with API credentials",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s WayHack CLI Setup\n", blue("🔧"))
			fmt.Println()
			fmt.Printf("%s To get your API key:\n", yellow("📝"))
			fmt.Printf("%s 1. Go to your API server's settings page\n", gray(""))
			fmt.Printf("%s 2. Navigate to the 'CLI API Keys' section\n", gray(""))
			fmt.Printf("%s 3. Click 'Create API Key' and copy the generated key\n", gray(""))
			fmt.Println()

			// Get API URL
			fmt.Print("Enter your WayHack API URL (https://wayhack.sh): ")
			reader := bufio.NewReader(os.Stdin)
			apiUrl, _ := reader.ReadString('\n')
			apiUrl = strings.TrimSpace(apiUrl)
			if apiUrl == "" {
				apiUrl = "https://wayhack.sh"
			}

			// Get API Key
			fmt.Print("Enter your API key (starts with wh_): ")
			apiKeyBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("\n%s Failed to read API key\n", red("❌"))
				return
			}
			fmt.Println()
			apiKey := strings.TrimSpace(string(apiKeyBytes))

			if !strings.HasPrefix(apiKey, "wh_") {
				fmt.Printf("%s API key should start with 'wh_'\n", red("❌"))
				return
			}

			fmt.Printf("%s Verifying API connection...\n", yellow("⏳"))

			// Verify API connection
			if verifyAPI(apiUrl, apiKey) {
				fmt.Printf("%s API connection verified!\n", green("✅"))
				config.APIUrl = apiUrl
				config.APIKey = apiKey
				saveConfig()
				fmt.Printf("%s Setup completed successfully!\n", green("✅"))
				fmt.Println()
				fmt.Printf("%s You can now use the following commands:\n", blue("🚀"))
				fmt.Printf("%s  wayhack check    - Check installed tools\n", gray(""))
				fmt.Printf("%s  wayhack list     - List enabled tools\n", gray(""))
				fmt.Printf("%s  wayhack run <tool> <url> - Run a specific tool\n", gray(""))
			} else {
				fmt.Printf("%s API connection failed\n", red("❌"))
				fmt.Printf("%s Please check your API URL and key\n", red(""))
				fmt.Printf("%s Make sure your API key is valid and not expired\n", yellow("💡"))
			}
		},
	}
}

func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check which bug bounty tools are installed",
		Run: func(cmd *cobra.Command, args []string) {
			if config.APIUrl == "" || config.APIKey == "" {
				fmt.Printf("%s Please run \"wayhack setup\" first\n", red("❌"))
				return
			}

			// Check subscription status
			fmt.Printf("%s Checking subscription status...\n", yellow("⏳"))
			subscription, err := checkSubscriptionStatus()
			if err != nil {
				fmt.Printf("%s Failed to check subscription status: %v\n", red("❌"), err)
				return
			}

			if !subscription.HasCLIAccess {
				fmt.Printf("%s Premium subscription required\n", red("❌"))
				fmt.Printf("%s The WayHack CLI requires a premium subscription to use.\n", yellow(""))
				fmt.Printf("%s Please visit %s/plans to upgrade your account.\n", blue("🔗"), config.APIUrl)
				fmt.Printf("%s After upgrading, you'll have access to:\n", blue("✨"))
				fmt.Printf("%s  • CLI Tool Access\n", gray(""))
				fmt.Printf("%s  • Execute Tools in Parallel\n", gray(""))
				fmt.Printf("%s  • API Access\n", gray(""))
				fmt.Printf("%s  • Web-Based Reconnaissance\n", gray(""))
				fmt.Printf("%s  • Community Support\n", gray(""))
				return
			}

			fmt.Printf("%s Checking installed tools...\n", blue("🔍"))
			fmt.Println()

			tools := []string{"ffuf", "dirsearch", "nuclei", "gobuster", "httpx"}
			results := make(map[string]bool)

			for _, tool := range tools {
				fmt.Printf("%s Checking %s...\n", yellow("⏳"), tool)
				isInstalled := checkToolInstalled(tool)
				results[tool] = isInstalled

				if isInstalled {
					fmt.Printf("%s %s is installed\n", green("✅"), tool)
				} else {
					fmt.Printf("%s %s is not installed\n", red("❌"), tool)
				}
			}

			fmt.Println()
			fmt.Printf("%s Summary:\n", blue("📊"))
			for _, tool := range tools {
				if results[tool] {
					fmt.Printf("%s %s: installed\n", green("✅"), green(tool))
				} else {
					fmt.Printf("%s %s: not installed\n", red("❌"), red(tool))
				}
			}
		},
	}
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [tool] [args...]",
		Short: "Run a tool command directly",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if config.APIUrl == "" || config.APIKey == "" {
				fmt.Printf("%s Please run \"wayhack setup\" first\n", red("❌"))
				return
			}

			// Check subscription status
			fmt.Printf("%s Checking subscription status...\n", yellow("⏳"))
			subscription, err := checkSubscriptionStatus()
			if err != nil {
				fmt.Printf("%s Failed to check subscription status: %v\n", red("❌"), err)
				return
			}

			if !subscription.HasCLIAccess {
				fmt.Printf("%s Premium subscription required\n", red("❌"))
				fmt.Printf("%s The WayHack CLI requires a premium subscription to use.\n", yellow(""))
				fmt.Printf("%s Please visit %s/plans to upgrade your account.\n", blue("🔗"), config.APIUrl)
				fmt.Printf("%s After upgrading, you'll have access to:\n", blue("✨"))
				fmt.Printf("%s  • CLI Tool Access\n", gray(""))
				fmt.Printf("%s  • Execute Tools in Parallel\n", gray(""))
				fmt.Printf("%s  • API Access\n", gray(""))
				fmt.Printf("%s  • Web-Based Reconnaissance\n", gray(""))
				fmt.Printf("%s  • Community Support\n", gray(""))
				return
			}

			if len(args) == 0 {
				fmt.Printf("%s Please provide a command to run\n", red("❌"))
				fmt.Printf("%s Example: wayhack run ffuf -u http://example.com/FUZZ -w wordlist.txt\n", yellow(""))
				return
			}

			toolName := args[0]
			toolArgs := args[1:]

			// Build the complete command string for display
			fullCommand := fmt.Sprintf("%s %s", toolName, strings.Join(toolArgs, " "))
			fmt.Printf("%s Running: %s\n", blue("🚀"), fullCommand)
			fmt.Println()

			// Check if tool is installed
			if !checkToolInstalled(toolName) {
				fmt.Printf("%s %s is not installed on your system\n", red("❌"), toolName)
				fmt.Printf("%s Please install %s first\n", yellow(""), toolName)
				return
			}

			// Extract target URL from arguments for metadata
			target := extractTarget(toolArgs)

			// Execute the command with output tracking
			scanID, err := executeWithTracking(toolName, toolArgs, fullCommand, target)
			if err != nil {
				fmt.Printf("%s Command execution failed: %v\n", red("❌"), err)
				return
			}

			fmt.Printf("%s Command completed successfully\n", green("✅"))
			fmt.Printf("%s Scan ID: %s\n", blue("📋"), scanID)
			fmt.Printf("%s Use 'wayhack view %s' to see the output\n", yellow("💡"), scanID)
		},
	}

	return cmd
}

func generateCmd() *cobra.Command {
	var category string
	var interactive bool

	cmd := &cobra.Command{
		Use:   "generate [tool] [url]",
		Short: "Generate commands for a specific tool and URL",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if config.APIUrl == "" || config.APIKey == "" {
				fmt.Printf("%s Please run \"wayhack setup\" first\n", red("❌"))
				return
			}

			// Check subscription status
			fmt.Printf("%s Checking subscription status...\n", yellow("⏳"))
			subscription, err := checkSubscriptionStatus()
			if err != nil {
				fmt.Printf("%s Failed to check subscription status: %v\n", red("❌"), err)
				return
			}

			if !subscription.HasCLIAccess {
				fmt.Printf("%s Premium subscription required\n", red("❌"))
				fmt.Printf("%s The WayHack CLI requires a premium subscription to use.\n", yellow(""))
				fmt.Printf("%s Please visit %s/plans to upgrade your account.\n", blue("🔗"), config.APIUrl)
				fmt.Printf("%s After upgrading, you'll have access to:\n", blue("✨"))
				fmt.Printf("%s  • CLI Tool Access\n", gray(""))
				fmt.Printf("%s  • Execute Tools in Parallel\n", gray(""))
				fmt.Printf("%s  • API Access\n", gray(""))
				fmt.Printf("%s  • Web-Based Reconnaissance\n", gray(""))
				fmt.Printf("%s  • Community Support\n", gray(""))
				return
			}

			tool := args[0]
			url := args[1]

			// Check if tool is installed
			if !checkToolInstalled(tool) {
				fmt.Printf("%s %s is not installed on your system\n", red("❌"), tool)
				fmt.Printf("%s Please install %s first\n", yellow(""), tool)
				return
			}

			fmt.Printf("%s Generating commands for %s...\n", yellow("⏳"), tool)

			commands, err := generateCommands(tool, url)
			if err != nil {
				fmt.Printf("%s Failed to generate commands: %v\n", red("❌"), err)
				return
			}

			fmt.Printf("%s Commands generated!\n", green("✅"))

			// Filter by category if specified
			if category != "" {
				var filtered []Command
				for _, cmd := range commands {
					if strings.Contains(strings.ToLower(cmd.Category), strings.ToLower(category)) {
						filtered = append(filtered, cmd)
					}
				}
				commands = filtered
			}

			if len(commands) == 0 {
				fmt.Printf("%s No commands found for the specified criteria\n", yellow(""))
				return
			}

			if interactive {
				// Interactive mode
				fmt.Println()
				fmt.Printf("%s Select a command to run:\n", blue(""))
				for i, cmd := range commands {
					fmt.Printf("%s %d. %s (%s)\n", gray(""), i+1, cmd.Description, cmd.Category)
				}

				fmt.Print("Enter selection (number): ")
				reader := bufio.NewReader(os.Stdin)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)

				index, err := strconv.Atoi(input)
				if err != nil || index < 1 || index > len(commands) {
					fmt.Printf("%s Invalid selection\n", red("❌"))
					return
				}

				selectedCommand := commands[index-1]
				fmt.Println()
				fmt.Printf("%s Running command:\n", blue(""))
				fmt.Printf("%s %s\n", gray(""), selectedCommand.Command)
				fmt.Println()

				// Parse and execute the command
				parts := parseCommand(selectedCommand.Command)
				if len(parts) == 0 {
					fmt.Printf("%s Invalid command\n", red("❌"))
					return
				}

				execCmd := exec.Command(parts[0], parts[1:]...)
				execCmd.Stdout = os.Stdout
				execCmd.Stderr = os.Stderr
				execCmd.Stdin = os.Stdin

				err = execCmd.Run()
				fmt.Println()

				if err != nil {
					if exitError, ok := err.(*exec.ExitError); ok {
						fmt.Printf("%s Command failed with exit code %d\n", red("❌"), exitError.ExitCode())
					} else {
						fmt.Printf("%s Command execution failed: %v\n", red("❌"), err)
					}
				} else {
					fmt.Printf("%s Command completed successfully\n", green("✅"))
				}
			} else {
				// List all commands
				fmt.Println()
				fmt.Printf("%s Available commands for %s:\n", blue("📋"), tool)
				fmt.Println()

				for i, cmd := range commands {
					fmt.Printf("%s %d. %s\n", cyan(""), i+1, cmd.Description)
					fmt.Printf("%s    Category: %s\n", gray(""), cmd.Category)
					fmt.Printf("%s    Command: %s\n", white(""), cmd.Command)
					fmt.Println()
				}

				fmt.Printf("%s Use --interactive flag to run commands interactively\n", yellow("💡"))
				fmt.Printf("%s Use 'wayhack run <command>' to execute commands directly\n", yellow("💡"))
			}
		},
	}

	cmd.Flags().StringVarP(&category, "category", "c", "", "Filter by command category")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive mode to select commands")

	return cmd
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available tools and their status",
		Run: func(cmd *cobra.Command, args []string) {
			if config.APIUrl == "" || config.APIKey == "" {
				fmt.Printf("%s Please run \"wayhack setup\" first\n", red("❌"))
				return
			}

			// Check subscription status
			fmt.Printf("%s Checking subscription status...\n", yellow("⏳"))
			subscription, err := checkSubscriptionStatus()
			if err != nil {
				fmt.Printf("%s Failed to check subscription status: %v\n", red("❌"), err)
				return
			}

			if !subscription.HasCLIAccess {
				fmt.Printf("%s Premium subscription required\n", red("❌"))
				fmt.Printf("%s The WayHack CLI requires a premium subscription to use.\n", yellow(""))
				fmt.Printf("%s Please visit %s/plans to upgrade your account.\n", blue("🔗"), config.APIUrl)
				fmt.Printf("%s After upgrading, you'll have access to:\n", blue("✨"))
				fmt.Printf("%s  • CLI Tool Access\n", gray(""))
				fmt.Printf("%s  • Execute Tools in Parallel\n", gray(""))
				fmt.Printf("%s  • API Access\n", gray(""))
				fmt.Printf("%s  • Web-Based Reconnaissance\n", gray(""))
				fmt.Printf("%s  • Community Support\n", gray(""))
				return
			}

			fmt.Printf("%s Fetching enabled tools...\n", yellow("⏳"))

			enabledTools, err := getEnabledTools()
			if err != nil {
				fmt.Printf("%s Failed to fetch tools: %v\n", red("❌"), err)
				return
			}

			fmt.Printf("%s Tools fetched!\n", green("✅"))
			fmt.Println()
			fmt.Printf("%s Enabled tools:\n", blue("🛠️"))

			for _, tool := range enabledTools {
				isInstalled := checkToolInstalled(tool)
				status := red("❌ Not installed")
				if isInstalled {
					status = green("✅ Installed")
				}
				fmt.Printf("  %s: %s\n", tool, status)
			}
		},
	}
}

func listenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Listen for commands from the server",
		Long: `Listen for commands from the server and execute them in the background.

This command will continuously poll the server for new commands and execute them automatically.
The listener will automatically stop after 5 hours to prevent indefinite running.

Examples:
  wayhack listen                    Start listening for commands
  wayhack listen --interval 5      Check for commands every 5 seconds`,
		Run: func(cmd *cobra.Command, args []string) {
			interval, _ := cmd.Flags().GetInt("interval")

			if config.APIUrl == "" || config.APIKey == "" {
				fmt.Printf("%s Please run \"wayhack setup\" first\n", red("❌"))
				return
			}

			// Check subscription status
			fmt.Printf("%s Checking subscription status...\n", yellow("⏳"))
			subscription, err := checkSubscriptionStatus()
			if err != nil {
				fmt.Printf("%s Failed to check subscription status: %v\n", red("❌"), err)
				return
			}

			if !subscription.HasCLIAccess {
				fmt.Printf("%s Premium subscription required\n", red("❌"))
				fmt.Printf("%s The WayHack CLI requires a premium subscription to use.\n", yellow(""))
				fmt.Printf("%s Please visit %s/plans to upgrade your account.\n", blue("🔗"), config.APIUrl)
				fmt.Printf("%s After upgrading, you'll have access to:\n", blue("✨"))
				fmt.Printf("%s  • CLI Tool Access\n", gray(""))
				fmt.Printf("%s  • Execute Tools in Parallel\n", gray(""))
				fmt.Printf("%s  • API Access\n", gray(""))
				fmt.Printf("%s  • Web-Based Reconnaissance\n", gray(""))
				fmt.Printf("%s  • Community Support\n", gray(""))
				return
			}

			fmt.Printf("%s Starting WayHack CLI listener...\n", blue("🎧"))
			fmt.Printf("%s Checking for commands every %d seconds\n", gray(""), interval)
			fmt.Printf("%s Maximum runtime: 5 hours\n", gray(""))
			fmt.Printf("%s Press Ctrl+C to stop\n", yellow("💡"))
			fmt.Println()

			fmt.Printf("%s Listening for commands...\n", green("✅"))

			// Set up signal handling for graceful shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

			// Check immediately on start
			checkForCommands()

			// Listen loop with 5-hour timeout
			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			defer ticker.Stop()

			// 5-hour timeout timer
			timeout := time.NewTimer(5 * time.Hour)
			defer timeout.Stop()

			for {
				select {
				case <-ticker.C:
					checkForCommands()
				case <-timeout.C:
					fmt.Printf("%s Maximum runtime of 5 hours reached. Stopping listener...\n", yellow("⏰"))
					fmt.Printf("%s Listener stopped automatically\n", green("✅"))
					return
				case <-sigChan:
					fmt.Printf("\n%s Received interrupt signal. Stopping listener...\n", yellow("⚠️"))
					fmt.Printf("%s Listener stopped gracefully\n", green("✅"))
					return
				}
			}
		},
	}

	cmd.Flags().IntP("interval", "i", 5, "Interval in seconds to check for new commands")
	return cmd
}

func checkForCommands() {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", config.APIUrl+"/api/cli/commands", nil)
	if err != nil {
		fmt.Printf("%s Error creating request: %v\n", red("❌"), err)
		return
	}

	req.Header.Set("Authorization", "ApiKey "+config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s Error fetching commands: %v\n", red("❌"), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%s Server returned status %d\n", red("❌"), resp.StatusCode)
		return
	}

	var response struct {
		Commands []struct {
			ID        string `json:"id"`
			Command   string `json:"command"`
			Tool      string `json:"tool"`
			URL       string `json:"url"`
			UserID    string `json:"userId"`
			Timestamp string `json:"timestamp"`
			Status    string `json:"status"`
		} `json:"commands"`
		Count int `json:"count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Printf("%s Error decoding response: %v\n", red("❌"), err)
		return
	}

	if response.Count > 0 {
		fmt.Printf("%s Found %d pending command(s)\n", blue("⚡"), response.Count)

		for _, command := range response.Commands {
			if command.ID != "" {
				fmt.Printf("%s Processing command %s: %s\n", blue("⚡"), command.ID, command.Command)
				go processServerCommand(command.ID, command.Command, command.Tool, command.URL)
			}
		}
	}
}

func searchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search",
		Short: "Discover URLs and perform OSINT reconnaissance",
		Long: `Search for URLs, subdomains, and other information about a target domain.

This command performs URL discovery using various data sources including:
- Wayback Machine archives
- Certificate Transparency logs
- Common crawl data
- DNS records
- And more...

Results are automatically saved and can be viewed later using 'wayhack view'.`,
		Example: `  wayhack search --domain example.com
  wayhack search --domain example.com --sources wayback,crtsh
  wayhack search --domain example.com --include-subdomains
  wayhack search --domain example.com --extensions pdf,doc,xls
  wayhack search --domain example.com --path "/admin"
  wayhack search --domain example.com --output json
  wayhack search --domain example.com --only-params
  wayhack search --domain example.com --exclude-extensions js,css
  wayhack search --domain example.com --sort-by-uniqueness
  wayhack search --domain example.com --proxies proxy1,proxy2
  wayhack search --domain example.com --silent`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, _ := cmd.Flags().GetString("domain")
			sources, _ := cmd.Flags().GetString("sources")
			includeSubdomains, _ := cmd.Flags().GetBool("include-subdomains")
			extensions, _ := cmd.Flags().GetString("extensions")
			path, _ := cmd.Flags().GetString("path")
			outputFormat, _ := cmd.Flags().GetString("output")
			limit, _ := cmd.Flags().GetInt("limit")
			onlyParams, _ := cmd.Flags().GetBool("only-params")
			excludeExtensions, _ := cmd.Flags().GetString("exclude-extensions")
			sortByUniqueness, _ := cmd.Flags().GetBool("sort-by-uniqueness")
			proxies, _ := cmd.Flags().GetString("proxies")
			silent, _ := cmd.Flags().GetBool("silent")

			if domain == "" {
				if silent {
					fmt.Printf("{\"error\": \"Domain is required. Use --domain flag.\"}\n")
				} else {
					fmt.Printf("%s Domain is required. Use --domain flag.\n", red("❌"))
				}
				return
			}

			if !silent {
				fmt.Printf("%s Starting URL discovery for domain: %s\n", blue("🔍"), cyan(domain))
			}

			// Perform the search
			results, err := performSearch(domain, sources, includeSubdomains, extensions, path, outputFormat, limit, onlyParams, excludeExtensions, sortByUniqueness, proxies, silent)
			if err != nil {
				if silent {
					fmt.Printf("{\"error\": \"%s\"}\n", err.Error())
				} else {
					fmt.Printf("%s Search failed: %v\n", red("❌"), err)
				}
				return
			}

			if silent {
				// Return JSON response in silent mode
				jsonResponse := map[string]interface{}{
					"results": results,
					"total":   len(results),
				}
				jsonBytes, _ := json.Marshal(jsonResponse)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("%s Search completed successfully. Found %d results.\n", green("✅"), len(results))
				fmt.Printf("%s Results saved to outputs directory. Use 'wayhack view --latest' to see them.\n", blue("💾"))
			}
		},
	}

	cmd.Flags().StringP("domain", "d", "", "Target domain to search (required)")
	cmd.Flags().StringP("sources", "s", "wayback,crtsh,commoncrawl", "Comma-separated list of data sources")
	cmd.Flags().BoolP("include-subdomains", "i", false, "Include subdomains in search")
	cmd.Flags().StringP("extensions", "e", "", "Comma-separated list of file extensions to filter")
	cmd.Flags().StringP("path", "p", "", "Specific path to search for")
	cmd.Flags().IntP("limit", "l", 1000, "Maximum number of results to return")
	cmd.Flags().Bool("only-params", false, "Only return URLs with parameters")
	cmd.Flags().String("exclude-extensions", "", "Comma-separated list of file extensions to exclude")
	cmd.Flags().Bool("sort-by-uniqueness", false, "Sort results by uniqueness")
	cmd.Flags().String("proxies", "", "Comma-separated list of proxies to use")
	cmd.Flags().Bool("silent", false, "Silent mode - return JSON only without any output")

	cmd.MarkFlagRequired("domain")
	return cmd
}

func performSearch(domain, sources string, includeSubdomains bool, extensions, path, outputFormat string, limit int, onlyParams bool, excludeExtensions string, sortByUniqueness bool, proxies string, silent bool) ([]string, error) {
	if config.APIUrl == "" || config.APIKey == "" {
		return nil, fmt.Errorf("please run \"wayhack setup\" first")
	}

	// Check subscription status
	if !silent {
		fmt.Printf("%s Checking subscription status...\n", yellow("⏳"))
	}
	subscription, err := checkSubscriptionStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to check subscription status: %v", err)
	}

	if !subscription.HasCLIAccess {
		return nil, fmt.Errorf("premium subscription required for CLI access")
	}

	// Create scan metadata
	scanID := generateScanID()
	startTime := time.Now()

	// Ensure output directory exists even if API call fails
	outputsDir := getOutputsDir()
	scanDir := filepath.Join(outputsDir, scanID)
	mkdirErr := os.MkdirAll(scanDir, 0755)
	if mkdirErr != nil {
		return nil, fmt.Errorf("failed to create scan directory: %v", err)
	}

	// Function to save error metadata and files
	saveErrorResults := func(errorMsg string, statusCode int) {
		// Save error to file
		errorFile := filepath.Join(scanDir, "stderr.txt")
		os.WriteFile(errorFile, []byte(errorMsg), 0644)

		// Save metadata with error status
		duration := time.Since(startTime)
		commandStr := fmt.Sprintf("search --domain %s", domain)
		if sources != "wayback,crtsh,commoncrawl" {
			commandStr += fmt.Sprintf(" --sources %s", sources)
		}
		if includeSubdomains {
			commandStr += " --include-subdomains"
		}
		if extensions != "" {
			commandStr += fmt.Sprintf(" --extensions %s", extensions)
		}
		if path != "" {
			commandStr += fmt.Sprintf(" --path %s", path)
		}
		if limit != 1000 {
			commandStr += fmt.Sprintf(" --limit %d", limit)
		}
		if onlyParams {
			commandStr += " --only-params"
		}
		if excludeExtensions != "" {
			commandStr += fmt.Sprintf(" --exclude-extensions %s", excludeExtensions)
		}
		if sortByUniqueness {
			commandStr += " --sort-by-uniqueness"
		}
		if proxies != "" {
			commandStr += fmt.Sprintf(" --proxies %s", proxies)
		}
		if silent {
			commandStr += " --silent"
		}

		metadata := ScanMetadata{
			ID:        scanID,
			Tool:      "search",
			Command:   commandStr,
			Target:    domain,
			Timestamp: startTime,
			Duration:  duration.String(),
			Status:    "failed",
			OutputDir: scanDir,
			ExitCode:  statusCode,
		}

		if saveErr := saveScanMetadata(metadata); saveErr != nil && !silent {
			fmt.Printf("%s Warning: Failed to save scan metadata: %v\n", yellow("⚠️"), err)
		}
	}

	// Build search query URL with parameters to match frontend structure
	searchURL := config.APIUrl + "/api/urls/search"

	// Convert sources to JSON object format to match API expectations
	sourcesList := strings.Split(sources, ",")
	enabledProvidersMap := map[string]bool{
		"wayback":        false,
		"urlscan":        false,
		"alienvault":     false,
		"commoncrawl":    false,
		"shodan":         false,
		"profundis":      false,
		"virustotal":     false,
		"securitytrails": false,
		"censys":         false,
		"intelx":         false,
		"leakix":         false,
		"fofa":           false,
		"crtsh":          false,
		"netlas":         false,
		"builtwith":      false,
		"zoomeye":        false,
		"hunter":         false,
		"github":         false,
		"gitlab":         false,
		"dorki":          false,
	}

	// Enable specified sources
	for _, source := range sourcesList {
		source = strings.TrimSpace(source)
		if _, exists := enabledProvidersMap[source]; exists {
			enabledProvidersMap[source] = true
		}
	}

	// Convert to JSON string
	enabledProvidersJSON, _ := json.Marshal(enabledProvidersMap)
	enabledProviders := string(enabledProvidersJSON)

	// Build URL parameters with proper encoding
	params := url.Values{}
	params.Set("query", domain)
	params.Set("onlyParams", strconv.FormatBool(onlyParams))
	params.Set("excludeExtensions", excludeExtensions)
	params.Set("sortByUniqueness", strconv.FormatBool(sortByUniqueness))
	params.Set("enabledProviders", enabledProviders)
	params.Set("streamingEnabled", "false") // Always enable streaming
	params.Set("proxies", proxies)

	// Add CLI-specific parameters
	if includeSubdomains {
		params.Set("includeSubdomains", "true")
	}
	if extensions != "" {
		params.Set("extensions", extensions)
	}
	if path != "" {
		params.Set("path", path)
	}
	if outputFormat != "text" {
		params.Set("outputFormat", outputFormat)
	}
	if limit != 1000 {
		params.Set("limit", strconv.Itoa(limit))
	}

	// Construct final URL
	finalURL := searchURL + "?" + params.Encode()

	// Make API request to search endpoint
	client := &http.Client{Timeout: 300 * time.Second} // 5 minute timeout for searches

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "ApiKey "+config.APIKey)

	if !silent {
		fmt.Printf("%s Sending search request to API...\n", blue("📡"))
	}
	resp, err := client.Do(req)
	if err != nil {
		errorMsg := fmt.Sprintf("failed to make request: %v", err)
		saveErrorResults(errorMsg, -1)
		return nil, fmt.Errorf("%s", errorMsg)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		errorMsg := fmt.Sprintf("API request failed with status %d: %s", resp.StatusCode, string(body))
		saveErrorResults(errorMsg, resp.StatusCode)
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse response as unstructured JSON
	var searchResponse map[string]interface{}

	if err := json.Unmarshal(body, &searchResponse); err != nil {
		errorMsg := fmt.Sprintf("failed to parse response: %v", err)
		saveErrorResults(errorMsg, 0)
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Extract URLs from results
	var urls []string
	if results, ok := searchResponse["results"].([]interface{}); ok {
		for _, result := range results {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if url, ok := resultMap["url"].(string); ok {
					urls = append(urls, url)
				}
			}
		}
	}

	// Save results to file (directory already created earlier)

	// Save results based on output format
	var outputFile string
	switch outputFormat {
	case "json":
		outputFile = filepath.Join(scanDir, "stdout.txt")
		if err := os.WriteFile(outputFile, body, 0644); err != nil {
			errorMsg := fmt.Sprintf("failed to save JSON results: %v", err)
			saveErrorResults(errorMsg, 0)
			return nil, fmt.Errorf("%s", errorMsg)
		}
	case "csv":
		outputFile = filepath.Join(scanDir, "stdout.txt")
		csvContent := "URL,Source\n"
		if results, ok := searchResponse["results"].([]interface{}); ok {
			for _, result := range results {
				if resultMap, ok := result.(map[string]interface{}); ok {
					url, _ := resultMap["url"].(string)
					source, _ := resultMap["source"].(string)
					csvContent += fmt.Sprintf("%s,%s\n", url, source)
				}
			}
		}
		if err := os.WriteFile(outputFile, []byte(csvContent), 0644); err != nil {
			errorMsg := fmt.Sprintf("failed to save CSV results: %v", err)
			saveErrorResults(errorMsg, 0)
			return nil, fmt.Errorf("%s", errorMsg)
		}
	default: // text
		outputFile = filepath.Join(scanDir, "stdout.txt")
		textContent := strings.Join(urls, "\n")
		if err := os.WriteFile(outputFile, []byte(textContent), 0644); err != nil {
			errorMsg := fmt.Sprintf("failed to save text results: %v", err)
			saveErrorResults(errorMsg, 0)
			return nil, fmt.Errorf("%s", errorMsg)
		}
	}

	// Save metadata
	duration := time.Since(startTime)
	commandStr := fmt.Sprintf("search --domain %s", domain)
	if sources != "wayback,crtsh,commoncrawl" {
		commandStr += fmt.Sprintf(" --sources %s", sources)
	}
	if includeSubdomains {
		commandStr += " --include-subdomains"
	}
	if extensions != "" {
		commandStr += fmt.Sprintf(" --extensions %s", extensions)
	}
	if path != "" {
		commandStr += fmt.Sprintf(" --path %s", path)
	}
	if outputFormat != "text" {
		commandStr += fmt.Sprintf(" --output %s", outputFormat)
	}
	if limit != 1000 {
		commandStr += fmt.Sprintf(" --limit %d", limit)
	}
	if onlyParams {
		commandStr += " --only-params"
	}
	if excludeExtensions != "" {
		commandStr += fmt.Sprintf(" --exclude-extensions %s", excludeExtensions)
	}
	if sortByUniqueness {
		commandStr += " --sort-by-uniqueness"
	}
	if proxies != "" {
		commandStr += fmt.Sprintf(" --proxies %s", proxies)
	}
	if silent {
		commandStr += " --silent"
	}

	metadata := ScanMetadata{
		ID:        scanID,
		Tool:      "search",
		Command:   commandStr,
		Target:    domain,
		Timestamp: startTime,
		Duration:  duration.String(),
		Status:    "completed",
		OutputDir: scanDir,
		ExitCode:  0,
	}

	if err := saveScanMetadata(metadata); err != nil {
		fmt.Printf("%s Warning: Failed to save scan metadata: %v\n", yellow("⚠️"), err)
	}

	return urls, nil
}

func processServerCommand(commandID, command, tool, url string) {
	// Update command status to "running"
	updateCommandStatus(commandID, "running", "")

	// If no command provided, fall back to generating one
	if command == "" {
		// Check if tool is installed
		if !checkToolInstalled(tool) {
			fmt.Printf("%s Tool %s is not installed\n", red("❌"), tool)
			updateCommandStatus(commandID, "failed", "Tool not installed")
			return
		}

		// Generate command
		commands, err := generateCommands(tool, url)
		if err != nil {
			fmt.Printf("%s Error generating command for %s: %v\n", red("❌"), tool, err)
			updateCommandStatus(commandID, "failed", fmt.Sprintf("Command generation failed: %v", err))
			return
		}

		if len(commands) == 0 {
			fmt.Printf("%s No command generated for %s\n", yellow("⚠️"), tool)
			updateCommandStatus(commandID, "failed", "No command generated")
			return
		}

		// Use the first generated command
		command = commands[0].Command
	}

	// Execute the command with output tracking
	fmt.Printf("%s Executing: %s\n", green("🚀"), command)

	parts := parseCommand(command)
	if len(parts) == 0 {
		fmt.Printf("%s Invalid command: %s\n", red("❌"), command)
		updateCommandStatus(commandID, "failed", "Invalid command format")
		return
	}

	// Use output tracking for server commands too
	scanID, err := executeWithTracking(tool, parts[1:], command, url)
	if err != nil {
		fmt.Printf("%s Command execution failed: %v\n", red("❌"), err)
		updateCommandStatus(commandID, "failed", fmt.Sprintf("Execution failed: %v", err))
		return
	}

	fmt.Printf("%s Command completed successfully\n", green("✅"))
	fmt.Printf("%s Scan ID: %s\n", blue("📋"), scanID)

	// Read the output for server response
	scans, err := loadScanMetadata()
	if err == nil {
		for _, scan := range scans {
			if scan.ID == scanID {
				stdoutFile := filepath.Join(scan.OutputDir, "stdout.txt")
				if data, err := os.ReadFile(stdoutFile); err == nil {
					updateCommandStatus(commandID, "completed", string(data))
				} else {
					updateCommandStatus(commandID, "completed", "Command completed successfully")
				}
				return
			}
		}
	}

	updateCommandStatus(commandID, "completed", "Command completed successfully")
}

func updateCommandStatus(commandID, status, result string) {
	client := &http.Client{Timeout: 30 * time.Second}

	payload := map[string]interface{}{
		"commandId": commandID,
		"status":    status,
		"result":    result,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("%s Error marshaling status update: %v\n", red("❌"), err)
		return
	}

	req, err := http.NewRequest("POST", config.APIUrl+"/api/cli/commands", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("%s Error creating status update request: %v\n", red("❌"), err)
		return
	}

	req.Header.Set("Authorization", "ApiKey "+config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s Error updating command status: %v\n", red("❌"), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%s Failed to update command status, server returned %d\n", red("❌"), resp.StatusCode)
	}
}

func viewCmd() *cobra.Command {
	var latest bool
	var count int
	var tool string
	var detailed bool
	var stats bool
	var report bool
	var target string
	var format string
	var since string

	cmd := &cobra.Command{
		Use:   "view [scan-id]",
		Short: "View scan outputs and results",
		Long: `View scan outputs and results with various filtering options.

Examples:
  wayhack view                          List all scans
  wayhack view scan-id-123             View specific scan output
  wayhack view --latest                View latest scan
  wayhack view --latest --tool ffuf    View latest ffuf scan
  wayhack view --count 10              View last 10 scans
  wayhack view --count 5 --tool nuclei View last 5 nuclei scans
  wayhack view --detailed              List scans with detailed information

Statistics:
  wayhack view --stats                          Overall statistics
  wayhack view --stats --tool nuclei           Tool-specific statistics
  wayhack view --stats --target "example.com"  Target-specific statistics

Reports:
  wayhack view --report --target "example.com" --format html
  wayhack view --report --since "2024-03-01" --format pdf`,
		Run: func(cmd *cobra.Command, args []string) {
			// Check subscription status first (except for specific scan viewing)
			if len(args) == 0 && !stats && !report {
				if config.APIUrl == "" || config.APIKey == "" {
					fmt.Printf("%s Please run \"wayhack setup\" first\n", red("❌"))
					return
				}

				// Check subscription status
				fmt.Printf("%s Checking subscription status...\n", yellow("⏳"))
				subscription, err := checkSubscriptionStatus()
				if err != nil {
					fmt.Printf("%s Failed to check subscription status: %v\n", red("❌"), err)
					return
				}

				if !subscription.HasCLIAccess {
					fmt.Printf("%s Premium subscription required\n", red("❌"))
					fmt.Printf("%s The WayHack CLI requires a premium subscription to use.\n", yellow(""))
					fmt.Printf("%s Please visit %s/plans to upgrade your account.\n", blue("🔗"), config.APIUrl)
					fmt.Printf("%s After upgrading, you'll have access to:\n", blue("✨"))
					fmt.Printf("%s  • CLI Tool Access\n", gray(""))
					fmt.Printf("%s  • Execute Tools in Parallel\n", gray(""))
					fmt.Printf("%s  • API Access\n", gray(""))
					fmt.Printf("%s  • Web-Based Reconnaissance\n", gray(""))
					fmt.Printf("%s  • Community Support\n", gray(""))
					return
				}
			}

			if len(args) == 1 {
				// View specific scan
				scanID := args[0]
				viewScanOutput(scanID)
				return
			}

			// Handle statistics generation
			if stats {
				generateStatistics(tool, target)
				return
			}

			// Handle report generation
			if report {
				generateReport(target, format, since)
				return
			}

			// List scans with filters
			scans, err := loadScanMetadata()
			if err != nil {
				fmt.Printf("%s Failed to load scan metadata: %v\n", red("❌"), err)
				fmt.Printf("%s Output directory: %s\n", gray(""), getOutputsDir())
				return
			}

			if len(scans) == 0 {
				fmt.Printf("%s No scans found\n", yellow("📭"))
				fmt.Printf("%s Output directory: %s\n", gray(""), getOutputsDir())
				fmt.Printf("%s Run some tools first using 'wayhack run <tool> <args>'\n", gray(""))
				return
			}

			// Filter by tool if specified
			if tool != "" {
				var filtered []ScanMetadata
				for _, scan := range scans {
					if strings.EqualFold(scan.Tool, tool) {
						filtered = append(filtered, scan)
					}
				}
				scans = filtered
			}

			if len(scans) == 0 {
				fmt.Printf("%s No scans found for tool: %s\n", yellow("📭"), tool)
				return
			}

			// Sort by timestamp (newest first)
			for i := 0; i < len(scans)-1; i++ {
				for j := i + 1; j < len(scans); j++ {
					if scans[i].Timestamp.Before(scans[j].Timestamp) {
						scans[i], scans[j] = scans[j], scans[i]
					}
				}
			}

			if latest {
				// View latest scan
				if len(scans) > 0 {
					viewScanOutput(scans[0].ID)
				} else {
					fmt.Printf("%s No scans found\n", yellow("📭"))
				}
				return
			}

			// Limit count if specified
			if count > 0 && count < len(scans) {
				scans = scans[:count]
			}

			// Display scan list
			if detailed {
				listScansDetailed(scans)
			} else {
				listScansTable(scans)
			}

			fmt.Println()
			fmt.Printf("%s Use 'wayhack view <scan-id>' to view specific scan output\n", yellow("💡"))
			fmt.Printf("%s Use 'wayhack view --detailed' for more information\n", gray(""))
		},
	}

	cmd.Flags().BoolVarP(&latest, "latest", "l", false, "View latest scan")
	cmd.Flags().IntVarP(&count, "count", "c", 0, "Number of scans to show (0 = all)")
	cmd.Flags().StringVarP(&tool, "tool", "t", "", "Filter by tool name")
	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Show detailed scan information")
	cmd.Flags().BoolVar(&stats, "stats", false, "Generate summary statistics")
	cmd.Flags().BoolVar(&report, "report", false, "Generate comprehensive report")
	cmd.Flags().StringVar(&target, "target", "", "Filter by target (for stats/reports)")
	cmd.Flags().StringVar(&format, "format", "text", "Report format (text, html, pdf)")
	cmd.Flags().StringVar(&since, "since", "", "Filter scans since date (YYYY-MM-DD)")

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("WayHack CLI v%s\n", Version)
			fmt.Printf("Go %s\n", runtime.Version())
			fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}

// Helper functions

func getConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ConfigFileName
	}
	return filepath.Join(homeDir, ConfigFileName)
}

func loadConfig() {
	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return // Config doesn't exist yet
	}

	json.Unmarshal(data, &config)
}

func saveConfig() {
	configPath := getConfigPath()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Printf("%s Error: Could not save config file\n", red(""))
		return
	}

	os.WriteFile(configPath, data, 0600)
}

func checkToolInstalled(toolName string) bool {
	commands := map[string][]string{
		"ffuf":      {"ffuf", "-h"},
		"dirsearch": {"dirsearch", "-h"},
		"nuclei":    {"nuclei", "-h"},
		"gobuster":  {"gobuster", "-h"},
		"httpx":     {"httpx", "-h"},
	}

	cmdArgs, known := commands[toolName]
	if !known {
		// For unknown tools, check if binary exists in PATH
		_, err := exec.LookPath(toolName)
		return err == nil
	}

	// Try to run the command with -h to see if it responds
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Run()

	// Some tools exit with non-zero on -h, so we also check if the binary is in PATH
	if err != nil {
		_, lookErr := exec.LookPath(cmdArgs[0])
		return lookErr == nil
	}

	return true
}

func verifyAPI(apiUrl, apiKey string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", apiUrl+"/api/tools/enabled", nil)
	if err != nil {
		return false
	}

	req.Header.Set("Authorization", "ApiKey "+apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func generateCommands(tool, url string) ([]Command, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	payload := map[string]string{
		"tool": tool,
		"url":  url,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", config.APIUrl+"/api/tools/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "ApiKey "+config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed: %s", string(body))
	}

	var response GenerateResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return response.Commands, nil
}

func getEnabledTools() ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", config.APIUrl+"/api/tools/enabled", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "ApiKey "+config.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed: %s", string(body))
	}

	var response EnabledToolsResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return response.Tools, nil
}

func checkSubscriptionStatus() (*SubscriptionResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", config.APIUrl+"/api/user/subscription/status", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "ApiKey "+config.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed: %s", string(body))
	}

	var response SubscriptionResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func parseCommand(commandString string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	var quoteChar rune

	for _, char := range commandString {
		if (char == '"' || char == '\'') && !inQuotes {
			inQuotes = true
			quoteChar = char
		} else if char == quoteChar && inQuotes {
			inQuotes = false
			quoteChar = 0
		} else if char == ' ' && !inQuotes {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(char)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// Output tracking helper functions

func getOutputsDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return OutputsDir
	}
	return filepath.Join(homeDir, OutputsDir)
}

func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().Unix())
}

func extractTarget(args []string) string {
	// Look for common URL patterns in arguments
	for _, arg := range args {
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			return arg
		}
		if strings.Contains(arg, "://") {
			return arg
		}
	}

	// Look for -u, --url, -t, --target flags
	for i, arg := range args {
		if (arg == "-u" || arg == "--url" || arg == "-t" || arg == "--target") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-u=") || strings.HasPrefix(arg, "--url=") {
			return strings.SplitN(arg, "=", 2)[1]
		}
		if strings.HasPrefix(arg, "-t=") || strings.HasPrefix(arg, "--target=") {
			return strings.SplitN(arg, "=", 2)[1]
		}
	}

	return "unknown"
}

func executeWithTracking(toolName string, toolArgs []string, fullCommand, target string) (string, error) {
	scanID := generateScanID()
	startTime := time.Now()

	// Create output directory
	outputsDir := getOutputsDir()
	scanDir := filepath.Join(outputsDir, scanID)
	err := os.MkdirAll(scanDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create output files
	stdoutFile := filepath.Join(scanDir, "stdout.txt")
	stderrFile := filepath.Join(scanDir, "stderr.txt")

	// Create metadata
	metadata := ScanMetadata{
		ID:        scanID,
		Tool:      toolName,
		Command:   fullCommand,
		Target:    target,
		Timestamp: startTime,
		Status:    "running",
		OutputDir: scanDir,
	}

	// Save initial metadata
	err = saveScanMetadata(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to save metadata: %v", err)
	}

	// Execute command with output capture
	cmd := exec.Command(toolName, toolArgs...)

	// Create output files
	stdout, err := os.Create(stdoutFile)
	if err != nil {
		return "", fmt.Errorf("failed to create stdout file: %v", err)
	}
	defer stdout.Close()

	stderr, err := os.Create(stderrFile)
	if err != nil {
		return "", fmt.Errorf("failed to create stderr file: %v", err)
	}
	defer stderr.Close()

	// Use MultiWriter to write to both file and console
	cmd.Stdout = io.MultiWriter(os.Stdout, stdout)
	cmd.Stderr = io.MultiWriter(os.Stderr, stderr)
	cmd.Stdin = os.Stdin

	// Execute command
	err = cmd.Run()
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Update metadata with results
	metadata.Duration = duration.String()
	metadata.Status = "completed"
	metadata.ExitCode = 0

	if err != nil {
		metadata.Status = "failed"
		if exitError, ok := err.(*exec.ExitError); ok {
			metadata.ExitCode = exitError.ExitCode()
		} else {
			metadata.ExitCode = 1
		}
	}

	// Save final metadata
	err = saveScanMetadata(metadata)
	if err != nil {
		fmt.Printf("%s Warning: Failed to save final metadata: %v\n", yellow("⚠️"), err)
	}

	return scanID, nil
}

func saveScanMetadata(metadata ScanMetadata) error {
	outputsDir := getOutputsDir()
	metadataPath := filepath.Join(outputsDir, MetadataFile)

	// Load existing metadata
	var allMetadata []ScanMetadata
	if data, err := os.ReadFile(metadataPath); err == nil {
		json.Unmarshal(data, &allMetadata)
	}

	// Update or append metadata
	found := false
	for i, existing := range allMetadata {
		if existing.ID == metadata.ID {
			allMetadata[i] = metadata
			found = true
			break
		}
	}

	if !found {
		allMetadata = append(allMetadata, metadata)
	}

	// Save metadata
	data, err := json.MarshalIndent(allMetadata, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	err = os.MkdirAll(outputsDir, 0755)
	if err != nil {
		return err
	}

	return os.WriteFile(metadataPath, data, 0644)
}

func loadScanMetadata() ([]ScanMetadata, error) {
	outputsDir := getOutputsDir()
	metadataPath := filepath.Join(outputsDir, MetadataFile)

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []ScanMetadata{}, nil
		}
		return nil, err
	}

	var metadata []ScanMetadata
	err = json.Unmarshal(data, &metadata)
	return metadata, err
}

func listScansTable(scans []ScanMetadata) {
	fmt.Printf("%s Scan History (%d scans)\n", blue("📋"), len(scans))
	fmt.Println()
	fmt.Printf("%-12s %-10s %-8s %-20s %-30s %s\n", "ID", "Tool", "Status", "Timestamp", "Target", "Duration")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	for _, scan := range scans {
		statusIcon := green("✅")
		if scan.Status == "failed" {
			statusIcon = red("❌")
		} else if scan.Status == "running" {
			statusIcon = yellow("⏳")
		}

		timestamp := scan.Timestamp.Format("2006-01-02 15:04:05")
		target := scan.Target
		if len(target) > 25 {
			target = target[:22] + "..."
		}

		scanIDShort := scan.ID
		if len(scanIDShort) > 12 {
			scanIDShort = scanIDShort[:12]
		}

		fmt.Printf("%-12s %-10s %s %-7s %-20s %-30s %s\n",
			scanIDShort, scan.Tool, statusIcon, scan.Status, timestamp, target, scan.Duration)
	}
}

func listScansDetailed(scans []ScanMetadata) {
	fmt.Printf("%s Detailed Scan History (%d scans)\n", blue("📋"), len(scans))
	fmt.Println()

	for i, scan := range scans {
		if i > 0 {
			fmt.Printf("%s\n", strings.Repeat("-", 80))
		}

		statusIcon := green("✅")
		statusColor := green
		if scan.Status == "failed" {
			statusIcon = red("❌")
			statusColor = red
		} else if scan.Status == "running" {
			statusIcon = yellow("⏳")
			statusColor = yellow
		}

		fmt.Printf("%s Scan #%d\n", blue("🔍"), i+1)
		fmt.Printf("  ID:        %s\n", cyan(scan.ID))
		fmt.Printf("  Tool:      %s\n", scan.Tool)
		fmt.Printf("  Status:    %s %s", statusIcon, statusColor(scan.Status))
		if scan.ExitCode != 0 && scan.Status == "failed" {
			fmt.Printf(" (exit code: %d)", scan.ExitCode)
		}
		fmt.Println()
		fmt.Printf("  Target:    %s\n", scan.Target)
		fmt.Printf("  Command:   %s\n", gray(scan.Command))
		fmt.Printf("  Timestamp: %s\n", scan.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Duration:  %s\n", scan.Duration)
		fmt.Printf("  Output:    %s\n", gray(scan.OutputDir))

		// Check if output files exist and show their sizes
		stdoutFile := filepath.Join(scan.OutputDir, "stdout.txt")
		stderrFile := filepath.Join(scan.OutputDir, "stderr.txt")

		if info, err := os.Stat(stdoutFile); err == nil {
			size := formatFileSize(info.Size())
			fmt.Printf("  Stdout:    %s (%s)\n", gray("stdout.txt"), size)
		}

		if info, err := os.Stat(stderrFile); err == nil && info.Size() > 0 {
			size := formatFileSize(info.Size())
			fmt.Printf("  Stderr:    %s (%s)\n", gray("stderr.txt"), size)
		}
	}
}

func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func viewScanOutput(scanID string) {
	// Load metadata to find scan
	scans, err := loadScanMetadata()
	if err != nil {
		fmt.Printf("%s Failed to load scan metadata: %v\n", red("❌"), err)
		return
	}

	if len(scans) == 0 {
		fmt.Printf("%s No scans found\n", yellow("📭"))
		fmt.Printf("%s Run some tools first using 'wayhack run <tool> <args>'\n", gray(""))
		return
	}

	var targetScan *ScanMetadata
	var matches []ScanMetadata

	// Look for exact match first, then partial matches
	for _, scan := range scans {
		if scan.ID == scanID {
			targetScan = &scan
			break
		}
		if strings.HasPrefix(scan.ID, scanID) {
			matches = append(matches, scan)
		}
	}

	// If no exact match, check partial matches
	if targetScan == nil {
		if len(matches) == 1 {
			targetScan = &matches[0]
		} else if len(matches) > 1 {
			fmt.Printf("%s Multiple scans match '%s':\n", yellow("⚠️"), scanID)
			for _, match := range matches {
				fmt.Printf("  %s - %s (%s)\n", match.ID, match.Tool, match.Timestamp.Format("2006-01-02 15:04:05"))
			}
			fmt.Printf("%s Please use a more specific scan ID\n", yellow("💡"))
			return
		}
	}

	if targetScan == nil {
		fmt.Printf("%s Scan not found: %s\n", red("❌"), scanID)
		fmt.Printf("%s Use 'wayhack view' to list all scans\n", yellow("💡"))
		return
	}

	// Display scan information
	fmt.Printf("%s Scan Details\n", blue("📋"))
	fmt.Printf("%s\n", strings.Repeat("=", 50))
	fmt.Printf("ID:        %s\n", cyan(targetScan.ID))
	fmt.Printf("Tool:      %s\n", targetScan.Tool)
	fmt.Printf("Command:   %s\n", targetScan.Command)
	fmt.Printf("Target:    %s\n", targetScan.Target)
	fmt.Printf("Timestamp: %s\n", targetScan.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Duration:  %s\n", targetScan.Duration)

	// Status with color
	statusIcon := green("✅")
	statusColor := green
	if targetScan.Status == "failed" {
		statusIcon = red("❌")
		statusColor = red
	} else if targetScan.Status == "running" {
		statusIcon = yellow("⏳")
		statusColor = yellow
	}
	fmt.Printf("Status:    %s %s", statusIcon, statusColor(targetScan.Status))
	if targetScan.ExitCode != 0 {
		fmt.Printf(" (exit code: %d)", targetScan.ExitCode)
	}
	fmt.Println()
	fmt.Printf("Output Dir: %s\n", gray(targetScan.OutputDir))
	fmt.Println()

	// Display output files
	stdoutFile := filepath.Join(targetScan.OutputDir, "stdout.txt")
	stderrFile := filepath.Join(targetScan.OutputDir, "stderr.txt")

	// Check if output directory exists
	if _, err := os.Stat(targetScan.OutputDir); os.IsNotExist(err) {
		fmt.Printf("%s Output directory not found: %s\n", red("❌"), targetScan.OutputDir)
		fmt.Printf("%s The scan output may have been deleted\n", yellow("⚠️"))
		return
	}

	// Show stdout
	if data, err := os.ReadFile(stdoutFile); err == nil {
		if len(data) > 0 {
			fmt.Printf("%s Standard Output (%s):\n", green("📄"), formatFileSize(int64(len(data))))
			fmt.Printf("%s\n", strings.Repeat("-", 50))
			fmt.Print(string(data))
			if !strings.HasSuffix(string(data), "\n") {
				fmt.Println()
			}
			fmt.Printf("%s\n", strings.Repeat("-", 50))
		} else {
			fmt.Printf("%s Standard Output: %s\n", gray("📄"), gray("(empty)"))
		}
	} else {
		fmt.Printf("%s Standard Output: %s\n", red("📄"), red("(file not found)"))
	}
	fmt.Println()

	// Show stderr if there are errors
	if data, err := os.ReadFile(stderrFile); err == nil {
		if len(data) > 0 {
			fmt.Printf("%s Standard Error (%s):\n", red("📄"), formatFileSize(int64(len(data))))
			fmt.Printf("%s\n", strings.Repeat("-", 50))
			fmt.Print(string(data))
			if !strings.HasSuffix(string(data), "\n") {
				fmt.Println()
			}
			fmt.Printf("%s\n", strings.Repeat("-", 50))
			fmt.Println()
		}
	} else if !os.IsNotExist(err) {
		fmt.Printf("%s Error reading stderr file: %v\n", red("❌"), err)
	}

	fmt.Printf("%s Output files location: %s\n", blue("📁"), targetScan.OutputDir)
	fmt.Printf("%s Use 'wayhack view' to list all scans\n", gray("💡"))
}

func generateStatistics(toolFilter, targetFilter string) {
	scans, err := loadScanMetadata()
	if err != nil {
		fmt.Printf("%s Failed to load scan metadata: %v\n", red("❌"), err)
		return
	}

	if len(scans) == 0 {
		fmt.Printf("%s No scans found\n", yellow("📭"))
		return
	}

	// Filter scans
	filteredScans := filterScans(scans, toolFilter, targetFilter, "")

	fmt.Printf("%s Scan Statistics\n", blue("📊"))
	fmt.Printf("%s\n", strings.Repeat("=", 50))
	fmt.Println()

	// Overall statistics
	totalScans := len(filteredScans)
	successfulScans := 0
	failedScans := 0
	toolCounts := make(map[string]int)
	targetCounts := make(map[string]int)
	statusCounts := make(map[string]int)

	var totalDuration time.Duration
	oldestScan := time.Now()
	newestScan := time.Time{}

	for _, scan := range filteredScans {
		if scan.Status == "completed" {
			successfulScans++
		} else {
			failedScans++
		}

		toolCounts[scan.Tool]++
		targetCounts[scan.Target]++
		statusCounts[scan.Status]++

		// Parse duration
		if duration, err := time.ParseDuration(scan.Duration); err == nil {
			totalDuration += duration
		}

		// Track date range
		if scan.Timestamp.Before(oldestScan) {
			oldestScan = scan.Timestamp
		}
		if scan.Timestamp.After(newestScan) {
			newestScan = scan.Timestamp
		}
	}

	// Display overall statistics
	fmt.Printf("%s Overall Statistics:\n", cyan("📈"))
	fmt.Printf("  Total Scans: %s\n", green(fmt.Sprintf("%d", totalScans)))
	fmt.Printf("  Successful: %s\n", green(fmt.Sprintf("%d", successfulScans)))
	fmt.Printf("  Failed: %s\n", red(fmt.Sprintf("%d", failedScans)))
	if totalScans > 0 {
		successRate := float64(successfulScans) / float64(totalScans) * 100
		fmt.Printf("  Success Rate: %s\n", green(fmt.Sprintf("%.1f%%", successRate)))
	}
	fmt.Printf("  Total Duration: %s\n", yellow(totalDuration.String()))
	if totalScans > 0 {
		avgDuration := totalDuration / time.Duration(totalScans)
		fmt.Printf("  Average Duration: %s\n", yellow(avgDuration.String()))
	}
	fmt.Printf("  Date Range: %s to %s\n", gray(oldestScan.Format("2006-01-02")), gray(newestScan.Format("2006-01-02")))
	fmt.Println()

	// Tool statistics
	if len(toolCounts) > 0 {
		fmt.Printf("%s Tool Usage:\n", cyan("🛠️"))
		for tool, count := range toolCounts {
			percentage := float64(count) / float64(totalScans) * 100
			fmt.Printf("  %s: %s (%s)\n", tool, green(fmt.Sprintf("%d", count)), gray(fmt.Sprintf("%.1f%%", percentage)))
		}
		fmt.Println()
	}

	// Target statistics
	if len(targetCounts) > 0 && len(targetCounts) <= 10 {
		fmt.Printf("%s Target Usage:\n", cyan("🎯"))
		for target, count := range targetCounts {
			if target != "" {
				percentage := float64(count) / float64(totalScans) * 100
				fmt.Printf("  %s: %s (%s)\n", target, green(fmt.Sprintf("%d", count)), gray(fmt.Sprintf("%.1f%%", percentage)))
			}
		}
		fmt.Println()
	}

	// Status statistics
	if len(statusCounts) > 0 {
		fmt.Printf("%s Status Distribution:\n", cyan("📋"))
		for status, count := range statusCounts {
			percentage := float64(count) / float64(totalScans) * 100
			statusColor := green
			if status == "failed" {
				statusColor = red
			} else if status == "running" {
				statusColor = yellow
			}
			fmt.Printf("  %s: %s (%s)\n", status, statusColor(fmt.Sprintf("%d", count)), gray(fmt.Sprintf("%.1f%%", percentage)))
		}
	}
}

func generateReport(targetFilter, format, since string) {
	scans, err := loadScanMetadata()
	if err != nil {
		fmt.Printf("%s Failed to load scan metadata: %v\n", red("❌"), err)
		return
	}

	if len(scans) == 0 {
		fmt.Printf("%s No scans found\n", yellow("📭"))
		return
	}

	// Filter scans
	filteredScans := filterScans(scans, "", targetFilter, since)

	if len(filteredScans) == 0 {
		fmt.Printf("%s No scans found matching criteria\n", yellow("📭"))
		return
	}

	// Generate report based on format
	switch strings.ToLower(format) {
	case "html":
		generateHTMLReport(filteredScans, targetFilter)
	case "pdf":
		fmt.Printf("%s PDF report generation not yet implemented\n", yellow("⚠️"))
		fmt.Printf("%s Use --format html or --format text instead\n", gray(""))
	default:
		generateTextReport(filteredScans, targetFilter)
	}
}

func filterScans(scans []ScanMetadata, toolFilter, targetFilter, since string) []ScanMetadata {
	var filtered []ScanMetadata

	for _, scan := range scans {
		// Filter by tool
		if toolFilter != "" && !strings.EqualFold(scan.Tool, toolFilter) {
			continue
		}

		// Filter by target
		if targetFilter != "" && !strings.Contains(strings.ToLower(scan.Target), strings.ToLower(targetFilter)) {
			continue
		}

		// Filter by date
		if since != "" {
			sinceDate, err := time.Parse("2006-01-02", since)
			if err != nil {
				fmt.Printf("%s Invalid date format: %s (use YYYY-MM-DD)\n", red("❌"), since)
				return nil
			}
			if scan.Timestamp.Before(sinceDate) {
				continue
			}
		}

		filtered = append(filtered, scan)
	}

	return filtered
}

func generateTextReport(scans []ScanMetadata, targetFilter string) {
	reportTitle := "WayHack Scan Report"
	if targetFilter != "" {
		reportTitle += fmt.Sprintf(" - %s", targetFilter)
	}

	fmt.Printf("%s %s\n", blue("📄"), reportTitle)
	fmt.Printf("%s\n", strings.Repeat("=", len(reportTitle)+4))
	fmt.Printf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Total Scans: %d\n", len(scans))
	fmt.Println()

	// Sort scans by timestamp (newest first)
	for i := 0; i < len(scans)-1; i++ {
		for j := i + 1; j < len(scans); j++ {
			if scans[i].Timestamp.Before(scans[j].Timestamp) {
				scans[i], scans[j] = scans[j], scans[i]
			}
		}
	}

	// Display scan details
	for i, scan := range scans {
		fmt.Printf("%s Scan %d: %s\n", cyan("🔍"), i+1, scan.ID)
		fmt.Printf("  Tool: %s\n", scan.Tool)
		fmt.Printf("  Target: %s\n", scan.Target)
		fmt.Printf("  Command: %s\n", scan.Command)
		fmt.Printf("  Timestamp: %s\n", scan.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Duration: %s\n", scan.Duration)
		statusColor := green
		if scan.Status == "failed" {
			statusColor = red
		} else if scan.Status == "running" {
			statusColor = yellow
		}
		fmt.Printf("  Status: %s\n", statusColor(scan.Status))
		fmt.Printf("  Exit Code: %d\n", scan.ExitCode)
		fmt.Printf("  Output Dir: %s\n", scan.OutputDir)
		fmt.Println()
	}

	fmt.Printf("%s Report generated successfully\n", green("✅"))
}

func generateHTMLReport(scans []ScanMetadata, targetFilter string) {
	reportTitle := "WayHack Scan Report"
	if targetFilter != "" {
		reportTitle += fmt.Sprintf(" - %s", targetFilter)
	}

	// Create HTML content
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .scan { border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }
        .scan-header { background: #f8f9fa; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 5px 5px 0 0; }
        .status-completed { color: #27ae60; font-weight: bold; }
        .status-failed { color: #e74c3c; font-weight: bold; }
        .status-running { color: #f39c12; font-weight: bold; }
        .meta { color: #7f8c8d; font-size: 0.9em; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>%s</h1>
    <p class="meta">Generated: %s | Total Scans: %d</p>
`, reportTitle, reportTitle, time.Now().Format("2006-01-02 15:04:05"), len(scans))

	// Sort scans by timestamp (newest first)
	for i := 0; i < len(scans)-1; i++ {
		for j := i + 1; j < len(scans); j++ {
			if scans[i].Timestamp.Before(scans[j].Timestamp) {
				scans[i], scans[j] = scans[j], scans[i]
			}
		}
	}

	// Add scan details
	htmlContent += "\n    <h2>Scan Details</h2>\n"
	for i, scan := range scans {
		statusClass := "status-completed"
		if scan.Status == "failed" {
			statusClass = "status-failed"
		} else if scan.Status == "running" {
			statusClass = "status-running"
		}

		htmlContent += fmt.Sprintf(`
    <div class="scan">
        <div class="scan-header">
            <strong>Scan %d: %s</strong>
        </div>
        <table>
            <tr><th>Tool</th><td>%s</td></tr>
            <tr><th>Target</th><td>%s</td></tr>
            <tr><th>Command</th><td><code>%s</code></td></tr>
            <tr><th>Timestamp</th><td>%s</td></tr>
            <tr><th>Duration</th><td>%s</td></tr>
            <tr><th>Status</th><td><span class="%s">%s</span></td></tr>
            <tr><th>Exit Code</th><td>%d</td></tr>
            <tr><th>Output Directory</th><td><code>%s</code></td></tr>
        </table>
    </div>`,
			i+1, scan.ID, scan.Tool, scan.Target, scan.Command,
			scan.Timestamp.Format("2006-01-02 15:04:05"), scan.Duration,
			statusClass, scan.Status, scan.ExitCode, scan.OutputDir)
	}

	htmlContent += "\n</body>\n</html>"

	// Save HTML report
	filename := fmt.Sprintf("wayhack-report-%s.html", time.Now().Format("20060102-150405"))
	if targetFilter != "" {
		filename = fmt.Sprintf("wayhack-report-%s-%s.html", strings.ReplaceAll(targetFilter, ".", "-"), time.Now().Format("20060102-150405"))
	}

	err := os.WriteFile(filename, []byte(htmlContent), 0644)
	if err != nil {
		fmt.Printf("%s Failed to save HTML report: %v\n", red("❌"), err)
		return
	}

	fmt.Printf("%s HTML report generated: %s\n", green("✅"), filename)
	fmt.Printf("%s Open the file in your browser to view the report\n", gray(""))
}
