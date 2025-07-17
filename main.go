package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SSHManager struct {
	config *AppConfig
}

func main() {
	// Check for SSH binaries
	missingBinaries := checkSSHBinaries()
	if len(missingBinaries) > 0 {
		log.Printf("Warning: Missing SSH binaries: %s", strings.Join(missingBinaries, ", "))
		log.Printf("Please install OpenSSH with: sudo apt install openssh-server openssh-client (Ubuntu/Debian) or equivalent")
		log.Printf("SSH operations may fail without these binaries!")
	}

	// Ensure config directory exists
	if err := ensureConfigDir(); err != nil {
		log.Fatalf("Failed to create config directory: %v", err)
	}

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create manager
	manager := &SSHManager{
		config: config,
	}

	// Start session cleanup routine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sessionManager.CleanupExpiredSessions()
				rateLimiter.CleanupOldAttempts()
			}
		}
	}()

	// Setup HTTP routes
	http.HandleFunc("/login", manager.handleLogin)
	http.HandleFunc("/change-password", manager.handleChangePassword)
	http.HandleFunc("/logout", sessionAuth(manager.handleLogout, config))
	http.HandleFunc("/", sessionAuth(manager.handleIndex, config))
	http.HandleFunc("/server-config", sessionAuth(manager.handleServerConfig, config))

	http.HandleFunc("/ssh-control", sessionAuth(manager.handleSSHControl, config))
	http.HandleFunc("/stats", sessionAuth(manager.handleStats, config))
	http.HandleFunc("/add-key-pair", sessionAuth(manager.handleAddKeyPair, config))
	http.HandleFunc("/remove-key-pair", sessionAuth(manager.handleRemoveKeyPair, config))
	http.HandleFunc("/key-qr", sessionAuth(manager.handleKeyQR, config))
	http.HandleFunc("/api/stats", sessionAuth(manager.handleStatsAPI, config))
	http.HandleFunc("/api", sessionAuth(manager.handleAPI, config))

	// Backup management routes
	http.HandleFunc("/backups", sessionAuth(manager.handleBackups, config))
	http.HandleFunc("/download-backup", sessionAuth(manager.handleDownloadBackup, config))

	// Determine port to use
	port := strconv.Itoa(config.Web.Port)
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	log.Printf("Starting SSH Manager on port %s", port)
	log.Printf("Access the web interface at: http://localhost:%s", port)
	log.Printf("Username: admin (password is securely hashed)")

	// Show SSH daemon status
	if _, err := config.getSSHDStatus(); err == nil {
		log.Printf("SSH daemon status checked")
	} else {
		log.Printf("Warning: Unable to check SSH daemon status: %v", err)
	}

	// Show SSH binaries status
	if len(missingBinaries) == 0 {
		log.Printf("SSH binaries found: ssh, sshd, ssh-keygen, systemctl")
	}

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down...")
		os.Exit(0)
	}()

	// Start server
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func init() {
	// Check if we're running as root (helpful for SSH configuration management)
	if os.Geteuid() != 0 {
		fmt.Println("Note: Running without root privileges. Some SSH management operations may require sudo.")
		fmt.Println("For full functionality, consider running with appropriate permissions.")
	}
}
