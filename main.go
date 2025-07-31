package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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
	Version = "2.0.0"
	ConfigFileName = ".wayhack-config.json"
)

type Config struct {
	APIUrl string `json:"apiUrl"`
	APIKey string `json:"apiKey"`
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

Note: 
  - Use 'wayhack run' to execute tools directly with their full arguments
  - Use 'wayhack generate' to get AI-suggested commands from the API
  - Complex arguments with spaces or special characters are properly handled
  - Quotes in commands are preserved and passed correctly to tools`,
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
			fmt.Printf("%s 1. Go to https://wayhack.sh/settings\n", gray(""))
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

			// Execute the command
			execCmd := exec.Command(toolName, toolArgs...)
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr
			execCmd.Stdin = os.Stdin

			err := execCmd.Run()
			fmt.Println()

			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					fmt.Printf("%s Command failed with exit code %d\n", red("❌"), exitError.ExitCode())
				} else {
					fmt.Printf("%s Failed to start %s: %v\n", red("❌"), toolName, err)
				}
			} else {
				fmt.Printf("%s Command completed successfully\n", green("✅"))
			}
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

			fmt.Printf("%s Starting WayHack CLI listener...\n", blue("🎧"))
			fmt.Printf("%s Checking for commands every %d seconds\n", gray(""), interval)
			fmt.Printf("%s Maximum runtime: 5 hours\n", gray(""))
			fmt.Printf("%s Press Ctrl+C to stop\n", yellow("💡"))
			fmt.Println()

			fmt.Printf("%s Listening for commands...\n", green("✅"))

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
			if command.Status == "pending" {
				fmt.Printf("%s Processing command %s: %s\n", blue("⚡"), command.ID, command.Command)
				go processServerCommand(command.ID, command.Command, command.Tool, command.URL)
			}
		}
	}
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

	// Execute the command
	fmt.Printf("%s Executing: %s\n", green("🚀"), command)
	
	parts := parseCommand(command)
	if len(parts) == 0 {
		fmt.Printf("%s Invalid command: %s\n", red("❌"), command)
		updateCommandStatus(commandID, "failed", "Invalid command format")
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		fmt.Printf("%s Command execution failed: %v\n", red("❌"), err)
		updateCommandStatus(commandID, "failed", fmt.Sprintf("Execution failed: %v\nOutput: %s", err, string(output)))
		return
	}

	fmt.Printf("%s Command completed successfully\n", green("✅"))
	updateCommandStatus(commandID, "completed", string(output))
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
		"ffuf":      {"ffuf", "-V"},
		"dirsearch": {"dirsearch", "--version"},
		"nuclei":    {"nuclei", "-version"},
		"gobuster":  {"gobuster", "version"},
		"httpx":     {"httpx", "-version"},
	}

	cmdArgs, exists := commands[toolName]
	if !exists {
		// For unknown tools, just check if they exist in PATH
		_, err := exec.LookPath(toolName)
		return err == nil
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Run()
	return err == nil
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