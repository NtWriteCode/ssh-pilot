package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SSHStats represents SSH connection statistics
type SSHStats struct {
	ActiveConnections int
	TotalConnections  int
	FailedConnections int
	LastFailedAttempt time.Time
	SSHDStatus        string
	ConnectedUsers    []ConnectedUser
	RecentConnections []RecentConnection
}

type ConnectedUser struct {
	User     string
	Terminal string
	Host     string
	Started  time.Time
	Idle     string
}

type RecentConnection struct {
	User      string
	Host      string
	Timestamp time.Time
	Status    string // "success", "failed", "disconnect"
	Method    string // "password", "publickey"
}

// Check if SSH binaries are available
func checkSSHBinaries() []string {
	var missing []string

	binaries := []string{"ssh", "sshd", "ssh-keygen", "systemctl"}
	for _, binary := range binaries {
		if _, err := exec.LookPath(binary); err != nil {
			missing = append(missing, binary)
		}
	}

	return missing
}

// Generate SSH key pair
func generateSSHKeyPair(keyType string, bits int, comment string) (privateKeyPath, publicKey string, err error) {
	// Create ~/.ssh directory if it doesn't exist
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("failed to get home directory: %v", err)
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create .ssh directory: %v", err)
	}

	// Generate unique filename
	timestamp := time.Now().Format("20060102_150405")
	keyName := fmt.Sprintf("ssh_key_%s_%s", keyType, timestamp)
	privateKeyPath = filepath.Join(sshDir, keyName)
	publicKeyPath := privateKeyPath + ".pub"

	// Build ssh-keygen command
	var cmd *exec.Cmd
	switch keyType {
	case "rsa":
		if bits == 0 {
			bits = 4096 // Default RSA key size
		}
		cmd = exec.Command("ssh-keygen", "-t", keyType, "-b", strconv.Itoa(bits), "-f", privateKeyPath, "-N", "", "-C", comment)
	case "ed25519":
		cmd = exec.Command("ssh-keygen", "-t", keyType, "-f", privateKeyPath, "-N", "", "-C", comment)
	case "ecdsa":
		if bits == 0 {
			bits = 256 // Default ECDSA key size
		}
		cmd = exec.Command("ssh-keygen", "-t", keyType, "-b", strconv.Itoa(bits), "-f", privateKeyPath, "-N", "", "-C", comment)
	default:
		return "", "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Execute ssh-keygen
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("ssh-keygen failed: %v\nOutput: %s", err, string(output))
	}

	// Read the public key
	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read public key: %v", err)
	}

	return privateKeyPath, string(publicKeyData), nil
}

// Get SSH daemon status
func (c *AppConfig) getSSHDStatus() (string, error) {
	var status strings.Builder

	status.WriteString("=== SSH Daemon Status ===\n")

	// Check if sshd is running
	cmd := exec.Command("systemctl", "is-active", "ssh")
	output, err := cmd.Output()
	if err != nil {
		// Try alternative service name
		cmd = exec.Command("systemctl", "is-active", "sshd")
		output, err = cmd.Output()
	}

	serviceStatus := strings.TrimSpace(string(output))
	if err != nil || serviceStatus != "active" {
		status.WriteString("Service Status: ❌ NOT RUNNING\n")
	} else {
		status.WriteString("Service Status: ✅ RUNNING\n")
	}

	// Check SSH configuration file
	if _, err := os.Stat(c.SSHConfigPath); os.IsNotExist(err) {
		status.WriteString(fmt.Sprintf("Config File: ❌ MISSING (%s)\n", c.SSHConfigPath))

		// Provide diagnostics when config file is missing
		diag := c.DiagnoseSSHInstallation()
		status.WriteString("\n🔍 Installation Diagnostics:\n")
		for _, suggestion := range diag.Suggestions {
			status.WriteString(fmt.Sprintf("  • %s\n", suggestion))
		}
		return status.String(), nil
	} else {
		status.WriteString(fmt.Sprintf("Config File: ✅ EXISTS (%s)\n", c.SSHConfigPath))
	}

	// Try to read current SSH configuration
	sshConfig, err := c.ReadSSHServerConfig()
	if err != nil {
		status.WriteString(fmt.Sprintf("Config Reading: ❌ ERROR (%v)\n", err))
		return status.String(), nil
	}

	// Check SSH port
	status.WriteString(fmt.Sprintf("SSH Port: %d\n", sshConfig.Port))

	// Check host keys
	if _, err := os.Stat(sshConfig.HostKeyPath); os.IsNotExist(err) {
		status.WriteString(fmt.Sprintf("Host Key: ❌ MISSING (%s)\n", sshConfig.HostKeyPath))
	} else {
		status.WriteString(fmt.Sprintf("Host Key: ✅ EXISTS (%s)\n", sshConfig.HostKeyPath))
	}

	// Get listening ports
	cmd = exec.Command("ss", "-tlnp")
	output, err = cmd.Output()
	if err != nil {
		status.WriteString("Port Check: ❌ UNABLE TO CHECK\n")
	} else {
		portStr := fmt.Sprintf(":%d ", sshConfig.Port)
		if strings.Contains(string(output), portStr) {
			status.WriteString(fmt.Sprintf("Port %d: ✅ LISTENING\n", sshConfig.Port))
		} else {
			status.WriteString(fmt.Sprintf("Port %d: ❌ NOT LISTENING\n", sshConfig.Port))
		}
	}

	return status.String(), nil
}

// Start SSH daemon
func (c *AppConfig) startSSHD() error {
	// Try both possible service names
	cmd := exec.Command("systemctl", "start", "ssh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try alternative service name
		cmd = exec.Command("systemctl", "start", "sshd")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start SSH daemon: %v\nOutput: %s", err, string(output))
		}
	}
	return nil
}

// Stop SSH daemon
func (c *AppConfig) stopSSHD() error {
	cmd := exec.Command("systemctl", "stop", "ssh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try alternative service name
		cmd = exec.Command("systemctl", "stop", "sshd")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to stop SSH daemon: %v\nOutput: %s", err, string(output))
		}
	}
	return nil
}

// Restart SSH daemon
func (c *AppConfig) restartSSHD() error {
	// Test configuration first
	if err := c.testSSHDConfig(); err != nil {
		return fmt.Errorf("SSH configuration test failed: %v", err)
	}

	cmd := exec.Command("systemctl", "restart", "ssh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try alternative service name
		cmd = exec.Command("systemctl", "restart", "sshd")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to restart SSH daemon: %v\nOutput: %s", err, string(output))
		}
	}
	return nil
}

// Test SSH daemon configuration
func (c *AppConfig) testSSHDConfig() error {
	cmd := exec.Command("sshd", "-t", "-f", c.SSHConfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("configuration test failed: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// Get SSH statistics and connection information
func (c *AppConfig) getSSHStats() (*SSHStats, error) {
	stats := &SSHStats{
		ConnectedUsers:    []ConnectedUser{},
		RecentConnections: []RecentConnection{},
	}

	// Get SSH daemon status
	status, err := c.getSSHDStatus()
	if err != nil {
		return nil, err
	}
	stats.SSHDStatus = status

	// Get connected users using 'who' command
	cmd := exec.Command("who")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			// Parse 'who' output format
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				user := ConnectedUser{
					User:     fields[0],
					Terminal: fields[1],
					Started:  time.Now(), // Simplified - would need parsing
				}
				if len(fields) >= 4 {
					user.Host = fields[len(fields)-1]
				}
				stats.ConnectedUsers = append(stats.ConnectedUsers, user)
			}
		}
	}

	stats.ActiveConnections = len(stats.ConnectedUsers)

	// Get recent SSH connections from auth.log (simplified)
	// This would typically parse /var/log/auth.log for SSH events
	stats.TotalConnections = stats.ActiveConnections // Simplified

	return stats, nil
}

// Utility function to copy files
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		return err
	}

	return nil
}
