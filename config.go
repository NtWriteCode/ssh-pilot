package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"os/exec"

	"golang.org/x/crypto/bcrypt"
)

// SSHServerConfig represents the actual SSH daemon configuration
// This is read from and written to the actual sshd_config file
type SSHServerConfig struct {
	Port                   int    `json:"port"`
	PermitRootLogin        string `json:"permit_root_login"` // yes, no, prohibit-password
	PasswordAuthentication bool   `json:"password_authentication"`
	PubkeyAuthentication   bool   `json:"pubkey_authentication"`
	AllowUsers             string `json:"allow_users"`           // Space-separated list
	DenyUsers              string `json:"deny_users"`            // Space-separated list
	ClientAliveInterval    int    `json:"client_alive_interval"` // Seconds
	ClientAliveCountMax    int    `json:"client_alive_count_max"`
	MaxAuthTries           int    `json:"max_auth_tries"`
	MaxSessions            int    `json:"max_sessions"`
	MaxStartups            string `json:"max_startups"`     // e.g., "10:30:60"
	LoginGraceTime         int    `json:"login_grace_time"` // Seconds
	Banner                 string `json:"banner"`           // Path to banner file
	PrintMotd              bool   `json:"print_motd"`
	PrintLastLog           bool   `json:"print_last_log"`
	TCPKeepAlive           bool   `json:"tcp_keep_alive"`
	X11Forwarding          bool   `json:"x11_forwarding"`
	AllowTcpForwarding     string `json:"allow_tcp_forwarding"` // yes, no, local, remote
	GatewayPorts           string `json:"gateway_ports"`        // yes, no, clientspecified
	PermitTunnel           string `json:"permit_tunnel"`        // yes, no, point-to-point, ethernet
	// Advanced options
	Protocol                        string `json:"protocol"`        // 2 (SSH2 only recommended)
	LogLevel                        string `json:"log_level"`       // QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG
	SyslogFacility                  string `json:"syslog_facility"` // AUTH, AUTHPRIV, DAEMON, etc.
	StrictModes                     bool   `json:"strict_modes"`
	IgnoreRhosts                    bool   `json:"ignore_rhosts"`
	HostbasedAuthentication         bool   `json:"hostbased_authentication"`
	PermitEmptyPasswords            bool   `json:"permit_empty_passwords"`
	ChallengeResponseAuthentication bool   `json:"challenge_response_authentication"`
	KerberosAuthentication          bool   `json:"kerberos_authentication"`
	GSSAPIAuthentication            bool   `json:"gssapi_authentication"`
	UsePAM                          bool   `json:"use_pam"`
	// File paths - these are constant system paths
	ConfigPath         string `json:"config_path"`
	AuthorizedKeysFile string `json:"authorized_keys_file"`
	HostKeyPath        string `json:"host_key_path"`
}

// SSHServerDiagnostics represents potential issues with SSH server installation
type SSHServerDiagnostics struct {
	ConfigFileExists bool     `json:"config_file_exists"`
	ConfigFilePath   string   `json:"config_file_path"`
	SSHDInstalled    bool     `json:"sshd_installed"`
	SSHServiceName   string   `json:"ssh_service_name"` // "ssh", "sshd", or ""
	MissingPackages  []string `json:"missing_packages"`
	Suggestions      []string `json:"suggestions"`
	PermissionIssues bool     `json:"permission_issues"`
	SELinuxIssues    bool     `json:"selinux_issues"`
}

type SSHKeyPair struct {
	Name           string `json:"name"`
	Type           string `json:"type"` // rsa, ed25519, ecdsa
	Bits           int    `json:"bits"` // Key size for RSA/ECDSA
	Comment        string `json:"comment"`
	PublicKey      string `json:"public_key"`       // Content of .pub file
	PrivateKeyPath string `json:"private_key_path"` // Path to private key file
	CreatedAt      string `json:"created_at"`
	LastUsed       string `json:"last_used"`
	Notes          string `json:"notes"`
}

type WebConfig struct {
	Port                   int    `json:"port"`
	Password               string `json:"password"`
	SessionTimeout         int    `json:"session_timeout"`          // Minutes
	DefaultPasswordChanged bool   `json:"default_password_changed"` // Track if admin/admin was changed
	SecurityAcknowledged   bool   `json:"security_acknowledged"`    // Track if user acknowledged security warnings
}

type AppConfig struct {
	KeyPairs map[string]SSHKeyPair `json:"key_pairs"`
	Web      WebConfig             `json:"web"`

	// SSH server config file path (for reading actual config)
	SSHConfigPath string `json:"ssh_config_path"`

	// Server config - populated dynamically from actual SSH config file
	// This is not stored in JSON but loaded from the actual sshd_config
	Server SSHServerConfig `json:"-"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionManager handles user sessions
type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

// Simple rate limiting for login attempts
type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	BlockedUntil   time.Time
}

type RateLimiter struct {
	attempts map[string]*LoginAttempt
	mutex    sync.RWMutex
}

// Global instances
var sessionManager = &SessionManager{
	sessions: make(map[string]*Session),
}

var rateLimiter = &RateLimiter{
	attempts: make(map[string]*LoginAttempt),
}

const defaultConfigPath = "ssh-pilot.json"

func loadConfig() (*AppConfig, error) {
	config := &AppConfig{
		KeyPairs:      make(map[string]SSHKeyPair),
		SSHConfigPath: "/etc/ssh/sshd_config", // Default SSH config path
		Web: WebConfig{
			Port:           8081,
			Password:       "admin",
			SessionTimeout: 60,
		},
	}

	if _, err := os.Stat(defaultConfigPath); os.IsNotExist(err) {
		// Hash the default password before returning
		if hashedPassword, err := HashPassword(config.Web.Password); err == nil {
			config.Web.Password = hashedPassword
		}
		return config, nil
	}

	data, err := os.ReadFile(defaultConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Migrate old configs and set defaults
	if config.Web.Port == 0 {
		config.Web.Port = 8081
	}
	if config.Web.SessionTimeout == 0 {
		config.Web.SessionTimeout = 60
	}

	// SECURITY: Migrate plaintext passwords to hashed passwords
	if !strings.HasPrefix(config.Web.Password, "$2a$") && !strings.HasPrefix(config.Web.Password, "$2b$") {
		if hashedPassword, err := HashPassword(config.Web.Password); err == nil {
			config.Web.Password = hashedPassword
			if saveErr := config.save(); saveErr != nil {
				fmt.Printf("Warning: Failed to save hashed password to config: %v\n", saveErr)
			}
		} else {
			fmt.Printf("Warning: Failed to hash password: %v\n", err)
		}
	}

	// Load SSH server configuration from actual file
	config.refreshServerConfig()

	return config, nil
}

func (c *AppConfig) save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(defaultConfigPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

func ensureConfigDir() error {
	dir := filepath.Dir(defaultConfigPath)
	return os.MkdirAll(dir, 0755)
}

// Rate limiter methods
func (rl *RateLimiter) IsBlocked(ip string) bool {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	attempt, exists := rl.attempts[ip]
	if !exists {
		return false
	}

	return time.Now().Before(attempt.BlockedUntil)
}

func (rl *RateLimiter) RecordFailedAttempt(ip string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	attempt, exists := rl.attempts[ip]
	if !exists {
		attempt = &LoginAttempt{}
		rl.attempts[ip] = attempt
	}

	attempt.FailedAttempts++
	attempt.LastAttempt = time.Now()

	// Block for 15 minutes after 5 failed attempts
	if attempt.FailedAttempts >= 5 {
		attempt.BlockedUntil = time.Now().Add(15 * time.Minute)
	}
}

func (rl *RateLimiter) RecordSuccessfulLogin(ip string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	delete(rl.attempts, ip)
}

func (rl *RateLimiter) CleanupOldAttempts() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for ip, attempt := range rl.attempts {
		if attempt.LastAttempt.Before(cutoff) && time.Now().After(attempt.BlockedUntil) {
			delete(rl.attempts, ip)
		}
	}
}

// Session management functions
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (sm *SessionManager) CreateSession(userID string, timeoutMinutes int) (*Session, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(timeoutMinutes) * time.Minute),
	}

	sm.sessions[sessionID] = session
	return session, nil
}

func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists || time.Now().After(session.ExpiresAt) {
		if exists {
			delete(sm.sessions, sessionID)
		}
		return nil, false
	}

	return session, true
}

func (sm *SessionManager) DeleteSession(sessionID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	delete(sm.sessions, sessionID)
}

func (sm *SessionManager) CleanupExpiredSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	for id, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			delete(sm.sessions, id)
		}
	}
}

// Password utilities
func ValidatePassword(provided, stored string) bool {
	if !strings.HasPrefix(stored, "$2a$") && !strings.HasPrefix(stored, "$2b$") {
		return provided == stored
	}

	err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided))
	return err == nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// SSH Key management
func (c *AppConfig) addKeyPair(name string) error {
	if _, exists := c.KeyPairs[name]; exists {
		return fmt.Errorf("key pair %s already exists", name)
	}

	keyPair := SSHKeyPair{
		Name:           name,
		Type:           "ed25519",
		Bits:           0, // ed25519 doesn't use bits
		Comment:        "",
		PublicKey:      "",
		PrivateKeyPath: "",
		CreatedAt:      time.Now().Format(time.RFC3339),
		LastUsed:       "",
		Notes:          "",
	}

	c.KeyPairs[name] = keyPair
	return nil
}

func (c *AppConfig) removeKeyPair(name string) error {
	if _, exists := c.KeyPairs[name]; !exists {
		return fmt.Errorf("key pair %s does not exist", name)
	}

	delete(c.KeyPairs, name)
	return nil
}

// SSH Configuration file parsing functions

// parseBoolValue parses SSH config boolean values (yes/no, true/false, on/off)
func parseBoolValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "yes" || value == "true" || value == "on"
}

// parseIntValue safely parses integer values with fallback
func parseIntValue(value string, defaultVal int) int {
	if value == "" {
		return defaultVal
	}
	if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		return parsed
	}
	return defaultVal
}

// ReadSSHServerConfig reads and parses the actual sshd_config file
func (c *AppConfig) ReadSSHServerConfig() (*SSHServerConfig, error) {
	configPath := c.SSHConfigPath

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("SSH config file does not exist: %s", configPath)
	}

	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH config file: %v", err)
	}
	defer file.Close()

	// Default configuration values
	config := &SSHServerConfig{
		Port:                            22,
		PermitRootLogin:                 "prohibit-password",
		PasswordAuthentication:          true,
		PubkeyAuthentication:            true,
		AllowUsers:                      "",
		DenyUsers:                       "",
		ClientAliveInterval:             0,
		ClientAliveCountMax:             3,
		MaxAuthTries:                    6,
		MaxSessions:                     10,
		MaxStartups:                     "10:30:60",
		LoginGraceTime:                  120,
		Banner:                          "",
		PrintMotd:                       true,
		PrintLastLog:                    true,
		TCPKeepAlive:                    true,
		X11Forwarding:                   false,
		AllowTcpForwarding:              "yes",
		GatewayPorts:                    "no",
		PermitTunnel:                    "no",
		Protocol:                        "2",
		LogLevel:                        "INFO",
		SyslogFacility:                  "AUTH",
		StrictModes:                     true,
		IgnoreRhosts:                    true,
		HostbasedAuthentication:         false,
		PermitEmptyPasswords:            false,
		ChallengeResponseAuthentication: false,
		KerberosAuthentication:          false,
		GSSAPIAuthentication:            false,
		UsePAM:                          true,
		ConfigPath:                      configPath,
		AuthorizedKeysFile:              ".ssh/authorized_keys",
		HostKeyPath:                     "/etc/ssh/ssh_host_ed25519_key",
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split key and value
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")

		// Parse configuration values
		switch key {
		case "port":
			config.Port = parseIntValue(value, 22)
		case "permitrootlogin":
			config.PermitRootLogin = strings.ToLower(value)
		case "passwordauthentication":
			config.PasswordAuthentication = parseBoolValue(value)
		case "pubkeyauthentication":
			config.PubkeyAuthentication = parseBoolValue(value)
		case "allowusers":
			config.AllowUsers = value
		case "denyusers":
			config.DenyUsers = value
		case "clientaliveinterval":
			config.ClientAliveInterval = parseIntValue(value, 0)
		case "clientalivecountmax":
			config.ClientAliveCountMax = parseIntValue(value, 3)
		case "maxauthtries":
			config.MaxAuthTries = parseIntValue(value, 6)
		case "maxsessions":
			config.MaxSessions = parseIntValue(value, 10)
		case "maxstartups":
			config.MaxStartups = value
		case "logingracetime":
			config.LoginGraceTime = parseIntValue(value, 120)
		case "banner":
			config.Banner = value
		case "printmotd":
			config.PrintMotd = parseBoolValue(value)
		case "printlastlog":
			config.PrintLastLog = parseBoolValue(value)
		case "tcpkeepalive":
			config.TCPKeepAlive = parseBoolValue(value)
		case "x11forwarding":
			config.X11Forwarding = parseBoolValue(value)
		case "allowtcpforwarding":
			config.AllowTcpForwarding = strings.ToLower(value)
		case "gatewayports":
			config.GatewayPorts = strings.ToLower(value)
		case "permittunnel":
			config.PermitTunnel = strings.ToLower(value)
		case "protocol":
			config.Protocol = value
		case "loglevel":
			config.LogLevel = strings.ToUpper(value)
		case "syslogfacility":
			config.SyslogFacility = strings.ToUpper(value)
		case "strictmodes":
			config.StrictModes = parseBoolValue(value)
		case "ignorerhosts":
			config.IgnoreRhosts = parseBoolValue(value)
		case "hostbasedauthentication":
			config.HostbasedAuthentication = parseBoolValue(value)
		case "permitemptypasswords":
			config.PermitEmptyPasswords = parseBoolValue(value)
		case "challengeresponseauthentication":
			config.ChallengeResponseAuthentication = parseBoolValue(value)
		case "kerberosauthentication":
			config.KerberosAuthentication = parseBoolValue(value)
		case "gssapiauthentication":
			config.GSSAPIAuthentication = parseBoolValue(value)
		case "usepam":
			config.UsePAM = parseBoolValue(value)
		case "authorizedkeysfile":
			config.AuthorizedKeysFile = value
		case "hostkey":
			config.HostKeyPath = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SSH config file: %v", err)
	}

	return config, nil
}

// WriteSSHServerConfig writes the SSH server configuration to the actual sshd_config file
func (c *AppConfig) WriteSSHServerConfig(config *SSHServerConfig) error {
	configPath := c.SSHConfigPath

	// Check if we can write to the config file
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("SSH config file does not exist: %s", configPath)
	}

	// Create backup
	backupPath := configPath + ".backup." + time.Now().Format("20060102_150405")
	if err := copyFile(configPath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %v", err)
	}

	// Generate new configuration content
	var content strings.Builder
	content.WriteString("# SSH Daemon Configuration\n")
	content.WriteString("# Generated by SSH Manager on " + time.Now().Format(time.RFC3339) + "\n")
	content.WriteString("# Backup saved as: " + backupPath + "\n\n")

	// Write configuration values
	content.WriteString(fmt.Sprintf("Port %d\n", config.Port))
	content.WriteString(fmt.Sprintf("Protocol %s\n", config.Protocol))
	content.WriteString(fmt.Sprintf("LogLevel %s\n", config.LogLevel))
	content.WriteString(fmt.Sprintf("SyslogFacility %s\n", config.SyslogFacility))

	// Host keys
	content.WriteString(fmt.Sprintf("HostKey %s\n", config.HostKeyPath))

	// Authentication
	content.WriteString(fmt.Sprintf("PermitRootLogin %s\n", config.PermitRootLogin))
	content.WriteString(fmt.Sprintf("PasswordAuthentication %s\n", boolToYesNo(config.PasswordAuthentication)))
	content.WriteString(fmt.Sprintf("PubkeyAuthentication %s\n", boolToYesNo(config.PubkeyAuthentication)))

	if config.AllowUsers != "" {
		content.WriteString(fmt.Sprintf("AllowUsers %s\n", config.AllowUsers))
	}
	if config.DenyUsers != "" {
		content.WriteString(fmt.Sprintf("DenyUsers %s\n", config.DenyUsers))
	}

	// Connection settings
	content.WriteString(fmt.Sprintf("MaxAuthTries %d\n", config.MaxAuthTries))
	content.WriteString(fmt.Sprintf("MaxSessions %d\n", config.MaxSessions))
	content.WriteString(fmt.Sprintf("MaxStartups %s\n", config.MaxStartups))
	content.WriteString(fmt.Sprintf("LoginGraceTime %d\n", config.LoginGraceTime))

	if config.ClientAliveInterval > 0 {
		content.WriteString(fmt.Sprintf("ClientAliveInterval %d\n", config.ClientAliveInterval))
		content.WriteString(fmt.Sprintf("ClientAliveCountMax %d\n", config.ClientAliveCountMax))
	}

	// Security settings
	content.WriteString(fmt.Sprintf("StrictModes %s\n", boolToYesNo(config.StrictModes)))
	content.WriteString(fmt.Sprintf("IgnoreRhosts %s\n", boolToYesNo(config.IgnoreRhosts)))
	content.WriteString(fmt.Sprintf("HostbasedAuthentication %s\n", boolToYesNo(config.HostbasedAuthentication)))
	content.WriteString(fmt.Sprintf("PermitEmptyPasswords %s\n", boolToYesNo(config.PermitEmptyPasswords)))
	content.WriteString(fmt.Sprintf("ChallengeResponseAuthentication %s\n", boolToYesNo(config.ChallengeResponseAuthentication)))

	// Authentication methods
	content.WriteString(fmt.Sprintf("KerberosAuthentication %s\n", boolToYesNo(config.KerberosAuthentication)))
	content.WriteString(fmt.Sprintf("GSSAPIAuthentication %s\n", boolToYesNo(config.GSSAPIAuthentication)))
	content.WriteString(fmt.Sprintf("UsePAM %s\n", boolToYesNo(config.UsePAM)))

	// Display settings
	content.WriteString(fmt.Sprintf("PrintMotd %s\n", boolToYesNo(config.PrintMotd)))
	content.WriteString(fmt.Sprintf("PrintLastLog %s\n", boolToYesNo(config.PrintLastLog)))

	if config.Banner != "" {
		content.WriteString(fmt.Sprintf("Banner %s\n", config.Banner))
	}

	// Network settings
	content.WriteString(fmt.Sprintf("TCPKeepAlive %s\n", boolToYesNo(config.TCPKeepAlive)))

	// Forwarding settings
	content.WriteString(fmt.Sprintf("X11Forwarding %s\n", boolToYesNo(config.X11Forwarding)))
	content.WriteString(fmt.Sprintf("AllowTcpForwarding %s\n", config.AllowTcpForwarding))
	content.WriteString(fmt.Sprintf("GatewayPorts %s\n", config.GatewayPorts))
	content.WriteString(fmt.Sprintf("PermitTunnel %s\n", config.PermitTunnel))

	// Other settings
	content.WriteString(fmt.Sprintf("AuthorizedKeysFile %s\n", config.AuthorizedKeysFile))

	// Write to file
	if err := os.WriteFile(configPath, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write SSH config file: %v", err)
	}

	return nil
}

// DiagnoseSSHInstallation analyzes potential SSH installation issues
func (c *AppConfig) DiagnoseSSHInstallation() *SSHServerDiagnostics {
	diag := &SSHServerDiagnostics{
		ConfigFilePath:   c.SSHConfigPath,
		MissingPackages:  []string{},
		Suggestions:      []string{},
		PermissionIssues: false,
		SELinuxIssues:    false,
	}

	// Check if config file exists
	if _, err := os.Stat(c.SSHConfigPath); os.IsNotExist(err) {
		diag.ConfigFileExists = false
		diag.Suggestions = append(diag.Suggestions, "SSH server configuration file is missing")
	} else {
		diag.ConfigFileExists = true
	}

	// Check if sshd binary is installed
	if _, err := exec.LookPath("sshd"); err != nil {
		diag.SSHDInstalled = false
		diag.MissingPackages = append(diag.MissingPackages, "openssh-server")
		diag.Suggestions = append(diag.Suggestions, "Install SSH server package")
	} else {
		diag.SSHDInstalled = true
	}

	// Check which service name works
	if diag.SSHDInstalled {
		if exec.Command("systemctl", "status", "ssh").Run() == nil {
			diag.SSHServiceName = "ssh"
		} else if exec.Command("systemctl", "status", "sshd").Run() == nil {
			diag.SSHServiceName = "sshd"
		}
	}

	// Provide specific suggestions based on findings
	if !diag.ConfigFileExists && !diag.SSHDInstalled {
		diag.Suggestions = append(diag.Suggestions, "SSH server is not installed. Install it with:")

		// Detect OS and provide appropriate install command
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			diag.Suggestions = append(diag.Suggestions, "  sudo apt update && sudo apt install openssh-server")
		} else if _, err := os.Stat("/etc/redhat-release"); err == nil {
			diag.Suggestions = append(diag.Suggestions, "  sudo yum install openssh-server  # (CentOS/RHEL 7)")
			diag.Suggestions = append(diag.Suggestions, "  sudo dnf install openssh-server  # (CentOS/RHEL 8+, Fedora)")
		} else if _, err := os.Stat("/etc/arch-release"); err == nil {
			diag.Suggestions = append(diag.Suggestions, "  sudo pacman -S openssh")
		} else {
			diag.Suggestions = append(diag.Suggestions, "  Use your distribution's package manager to install openssh-server")
		}

		diag.Suggestions = append(diag.Suggestions, "After installation, enable and start the service:")
		diag.Suggestions = append(diag.Suggestions, "  sudo systemctl enable ssh")
		diag.Suggestions = append(diag.Suggestions, "  sudo systemctl start ssh")
	} else if !diag.ConfigFileExists && diag.SSHDInstalled {
		diag.Suggestions = append(diag.Suggestions, "SSH server is installed but config file is missing.")
		diag.Suggestions = append(diag.Suggestions, "Try reinstalling the openssh-server package:")

		if _, err := os.Stat("/etc/debian_version"); err == nil {
			diag.Suggestions = append(diag.Suggestions, "  sudo apt reinstall openssh-server")
		} else {
			diag.Suggestions = append(diag.Suggestions, "  Reinstall openssh-server using your package manager")
		}
	} else if diag.ConfigFileExists && !diag.SSHDInstalled {
		diag.Suggestions = append(diag.Suggestions, "Config file exists but SSH daemon is not installed.")
		diag.Suggestions = append(diag.Suggestions, "This is unusual - you may have a partial installation.")
	}

	// Check for permission issues
	if diag.ConfigFileExists {
		if info, err := os.Stat(c.SSHConfigPath); err == nil {
			// Check if we can read the file
			if _, err := os.Open(c.SSHConfigPath); err != nil {
				diag.PermissionIssues = true
				diag.Suggestions = append(diag.Suggestions, "Permission denied reading SSH config. You may need sudo privileges.")
			}

			// Warn about unusual permissions
			if info.Mode().Perm() != 0644 && info.Mode().Perm() != 0600 {
				diag.Suggestions = append(diag.Suggestions, fmt.Sprintf("Unusual file permissions on %s: %o", c.SSHConfigPath, info.Mode().Perm()))
			}
		}
	}

	// Check for SELinux issues (basic check)
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		// SELinux is present, add a note
		diag.Suggestions = append(diag.Suggestions, "SELinux is active. If you encounter issues, check SELinux policies for SSH.")
	}

	return diag
}

// SSH Configuration Backup Management

// BackupInfo represents information about a backup file
type BackupInfo struct {
	Path        string    `json:"path"`
	Filename    string    `json:"filename"`
	CreatedAt   time.Time `json:"created_at"`
	Size        int64     `json:"size"`
	Description string    `json:"description"`
	IsAutomatic bool      `json:"is_automatic"`
	ConfigHash  string    `json:"config_hash,omitempty"`
}

// BackupManager manages SSH configuration backups
type BackupManager struct {
	ConfigPath    string
	BackupDir     string
	MaxBackups    int
	RetentionDays int
}

// NewBackupManager creates a new backup manager
func (c *AppConfig) NewBackupManager() *BackupManager {
	backupDir := filepath.Dir(c.SSHConfigPath)
	return &BackupManager{
		ConfigPath:    c.SSHConfigPath,
		BackupDir:     backupDir,
		MaxBackups:    10, // Keep last 10 backups
		RetentionDays: 30, // Keep backups for 30 days
	}
}

// CreateBackup creates a backup of the SSH configuration file
func (bm *BackupManager) CreateBackup(description string, isAutomatic bool) (*BackupInfo, error) {
	// Check if source file exists
	if _, err := os.Stat(bm.ConfigPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("SSH config file does not exist: %s", bm.ConfigPath)
	}

	// Get file info
	fileInfo, err := os.Stat(bm.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %v", err)
	}

	// Generate backup filename
	timestamp := time.Now().Format("20060102_150405")
	var filename string
	if isAutomatic {
		filename = fmt.Sprintf("sshd_config.backup.%s", timestamp)
	} else {
		// For manual backups, include description in filename
		cleanDesc := strings.ReplaceAll(strings.ToLower(description), " ", "_")
		cleanDesc = strings.ReplaceAll(cleanDesc, "/", "_")
		if len(cleanDesc) > 20 {
			cleanDesc = cleanDesc[:20]
		}
		if cleanDesc != "" {
			filename = fmt.Sprintf("sshd_config.backup.%s.%s", timestamp, cleanDesc)
		} else {
			filename = fmt.Sprintf("sshd_config.backup.%s.manual", timestamp)
		}
	}

	backupPath := filepath.Join(bm.BackupDir, filename)

	// Create backup
	if err := copyFile(bm.ConfigPath, backupPath); err != nil {
		return nil, fmt.Errorf("failed to create backup: %v", err)
	}

	// Calculate config hash for integrity checking
	configContent, err := os.ReadFile(bm.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config for hash: %v", err)
	}
	hash := fmt.Sprintf("%x", configContent[:min(len(configContent), 32)]) // Simple hash

	backup := &BackupInfo{
		Path:        backupPath,
		Filename:    filename,
		CreatedAt:   time.Now(),
		Size:        fileInfo.Size(),
		Description: description,
		IsAutomatic: isAutomatic,
		ConfigHash:  hash,
	}

	return backup, nil
}

// ListBackups returns a list of all available backups
func (bm *BackupManager) ListBackups() ([]BackupInfo, error) {
	var backups []BackupInfo

	// Read directory
	files, err := os.ReadDir(bm.BackupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %v", err)
	}

	// Find backup files
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := file.Name()
		if !strings.HasPrefix(filename, "sshd_config.backup.") {
			continue
		}

		// Get file info
		fullPath := filepath.Join(bm.BackupDir, filename)
		fileInfo, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		// Parse timestamp from filename
		parts := strings.Split(filename, ".")
		if len(parts) < 3 {
			continue
		}

		timestampStr := parts[2]
		createdAt, err := time.Parse("20060102_150405", timestampStr)
		if err != nil {
			// Try to parse as just the timestamp part
			if len(parts) >= 3 {
				createdAt = fileInfo.ModTime()
			} else {
				continue
			}
		}

		// Determine if automatic or manual backup
		isAutomatic := !strings.Contains(filename, ".manual") && len(parts) == 3
		description := "Automatic backup"
		if !isAutomatic {
			if len(parts) > 3 {
				description = strings.ReplaceAll(parts[3], "_", " ")
				description = strings.Title(description)
			} else {
				description = "Manual backup"
			}
		}

		backup := BackupInfo{
			Path:        fullPath,
			Filename:    filename,
			CreatedAt:   createdAt,
			Size:        fileInfo.Size(),
			Description: description,
			IsAutomatic: isAutomatic,
		}

		backups = append(backups, backup)
	}

	// Sort by creation time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	return backups, nil
}

// RestoreBackup restores a backup file to the current SSH configuration
func (bm *BackupManager) RestoreBackup(backupPath string) error {
	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	// Create a backup of current config before restoring
	currentBackup, err := bm.CreateBackup("Before restore", true)
	if err != nil {
		return fmt.Errorf("failed to backup current config before restore: %v", err)
	}

	// Restore the backup
	if err := copyFile(backupPath, bm.ConfigPath); err != nil {
		return fmt.Errorf("failed to restore backup: %v", err)
	}

	// Test the restored configuration
	cmd := exec.Command("sshd", "-t", "-f", bm.ConfigPath)
	if err := cmd.Run(); err != nil {
		// Configuration is invalid, restore the current backup
		if restoreErr := copyFile(currentBackup.Path, bm.ConfigPath); restoreErr != nil {
			return fmt.Errorf("restored config is invalid and failed to restore previous config: %v (original error: %v)", restoreErr, err)
		}
		return fmt.Errorf("restored configuration is invalid, reverted to previous config: %v", err)
	}

	return nil
}

// CleanupOldBackups removes old backup files based on retention policy
func (bm *BackupManager) CleanupOldBackups() error {
	backups, err := bm.ListBackups()
	if err != nil {
		return fmt.Errorf("failed to list backups for cleanup: %v", err)
	}

	var toDelete []BackupInfo
	cutoffDate := time.Now().AddDate(0, 0, -bm.RetentionDays)

	// Mark old backups for deletion (keep at least the most recent ones)
	for i, backup := range backups {
		// Always keep the first MaxBackups
		if i < bm.MaxBackups {
			continue
		}

		// Delete if older than retention period
		if backup.CreatedAt.Before(cutoffDate) {
			toDelete = append(toDelete, backup)
		}
	}

	// Delete marked backups
	for _, backup := range toDelete {
		if err := os.Remove(backup.Path); err != nil {
			fmt.Printf("Warning: failed to delete old backup %s: %v\n", backup.Filename, err)
		} else {
			fmt.Printf("Deleted old backup: %s\n", backup.Filename)
		}
	}

	return nil
}

// GetBackupStats returns statistics about backups
func (bm *BackupManager) GetBackupStats() (map[string]interface{}, error) {
	backups, err := bm.ListBackups()
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_backups":    len(backups),
		"automatic_count":  0,
		"manual_count":     0,
		"total_size_bytes": int64(0),
		"oldest_backup":    "",
		"newest_backup":    "",
	}

	if len(backups) == 0 {
		return stats, nil
	}

	var totalSize int64
	automaticCount := 0
	manualCount := 0

	for _, backup := range backups {
		totalSize += backup.Size
		if backup.IsAutomatic {
			automaticCount++
		} else {
			manualCount++
		}
	}

	stats["automatic_count"] = automaticCount
	stats["manual_count"] = manualCount
	stats["total_size_bytes"] = totalSize
	stats["total_size_mb"] = float64(totalSize) / (1024 * 1024)
	stats["oldest_backup"] = backups[len(backups)-1].CreatedAt.Format("2006-01-02 15:04:05")
	stats["newest_backup"] = backups[0].CreatedAt.Format("2006-01-02 15:04:05")

	return stats, nil
}

// Enhanced WriteSSHServerConfig with improved backup management
func (c *AppConfig) WriteSSHServerConfigWithBackup(config *SSHServerConfig, backupDescription string) error {
	// Create backup manager
	bm := c.NewBackupManager()

	// Clean up old backups first
	if err := bm.CleanupOldBackups(); err != nil {
		fmt.Printf("Warning: failed to cleanup old backups: %v\n", err)
	}

	// Create backup with description
	backup, err := bm.CreateBackup(backupDescription, backupDescription == "")
	if err != nil {
		return fmt.Errorf("failed to create backup: %v", err)
	}

	fmt.Printf("Created backup: %s\n", backup.Filename)

	// Now write the new configuration
	return c.WriteSSHServerConfig(config)
}

// Utility functions
func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// Backward compatibility helpers for handlers

// GetServerConfig provides a Server field for backward compatibility with handlers
// This reads from the actual SSH config file
func (c *AppConfig) GetServerConfig() *SSHServerConfig {
	config, err := c.ReadSSHServerConfig()
	if err != nil {
		// Return default config if file doesn't exist
		return &SSHServerConfig{
			Port:                   22,
			PermitRootLogin:        "prohibit-password",
			PasswordAuthentication: true,
			PubkeyAuthentication:   true,
			ConfigPath:             c.SSHConfigPath,
			HostKeyPath:            "/etc/ssh/ssh_host_ed25519_key",
			AuthorizedKeysFile:     ".ssh/authorized_keys",
			MaxAuthTries:           6,
			MaxSessions:            10,
			ClientAliveCountMax:    3,
			LoginGraceTime:         120,
			LogLevel:               "INFO",
			Protocol:               "2",
			SyslogFacility:         "AUTH",
		}
	}
	return config
}

// UpdateServerConfig saves the server configuration to the actual SSH config file
func (c *AppConfig) UpdateServerConfig(serverConfig *SSHServerConfig) error {
	// Check if config file exists before trying to write
	if _, err := os.Stat(c.SSHConfigPath); os.IsNotExist(err) {
		return fmt.Errorf("SSH config file does not exist: %s. Please install SSH server first", c.SSHConfigPath)
	}

	return c.WriteSSHServerConfig(serverConfig)
}

// refreshServerConfig loads the SSH server config from the actual file into the Server field
func (c *AppConfig) refreshServerConfig() {
	if config, err := c.ReadSSHServerConfig(); err == nil {
		c.Server = *config
	} else {
		// Use default config if file doesn't exist
		c.Server = *c.GetServerConfig()
	}
}
