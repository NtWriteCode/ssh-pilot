package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// sessionAuth checks for valid session authentication
func sessionAuth(next http.HandlerFunc, config *AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for login page and login POST
		if r.URL.Path == "/login" {
			next(w, r)
			return
		}

		// Get session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			// No session cookie, redirect to login
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate session
		_, valid := sessionManager.GetSession(cookie.Value)
		if !valid {
			// Invalid session, redirect to login
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "",
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			})
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func (app *SSHManager) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data := struct {
			UsingDefaultPassword bool
		}{
			UsingDefaultPassword: !app.config.Web.DefaultPasswordChanged,
		}
		tmpl := template.Must(template.New("login").Parse(loginTemplate))
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Template execution error in handleLogin: %v", err)
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username != "admin" {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(app.config.Web.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Check if using default password (admin/admin)
		if !app.config.Web.DefaultPasswordChanged {
			defaultErr := bcrypt.CompareHashAndPassword([]byte(app.config.Web.Password), []byte("admin"))
			if defaultErr == nil {
				// Force password change
				http.Redirect(w, r, "/change-password?force=true", http.StatusSeeOther)
				return
			}
		}

		// Create session
		session, err := sessionManager.CreateSession("admin", app.config.Web.SessionTimeout)
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    session.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
			MaxAge:   app.config.Web.SessionTimeout * 60,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *SSHManager) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	forced := r.URL.Query().Get("force") == "true"

	switch r.Method {
	case "GET":
		data := struct {
			Forced bool
		}{
			Forced: forced,
		}
		tmpl := template.Must(template.New("changePassword").Parse(changePasswordTemplate))
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Template execution error in handleChangePassword: %v", err)
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
	case "POST":
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")
		acknowledged := r.FormValue("security_acknowledged") == "on"

		if newPassword == "" {
			http.Error(w, "Password cannot be empty", http.StatusBadRequest)
			return
		}

		if newPassword != confirmPassword {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		if len(newPassword) < 8 {
			http.Error(w, "Password must be at least 8 characters long", http.StatusBadRequest)
			return
		}

		if newPassword == "admin" {
			http.Error(w, "Cannot use 'admin' as password", http.StatusBadRequest)
			return
		}

		if !acknowledged {
			http.Error(w, "You must acknowledge the security warnings", http.StatusBadRequest)
			return
		}

		// Hash the new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		// Update configuration
		app.config.Web.Password = string(hashedPassword)
		app.config.Web.DefaultPasswordChanged = true
		app.config.Web.SecurityAcknowledged = acknowledged

		// Save configuration
		if err := app.config.save(); err != nil {
			log.Printf("Error saving config: %v", err)
			http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
			return
		}

		// If this was a forced change, create session and redirect to dashboard
		if forced {
			session, err := sessionManager.CreateSession("admin", app.config.Web.SessionTimeout)
			if err != nil {
				http.Error(w, "Failed to create session", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    session.ID,
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
				MaxAge:   app.config.Web.SessionTimeout * 60,
			})
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *SSHManager) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get session cookie
		if cookie, err := r.Cookie("session_id"); err == nil {
			// Delete session
			sessionManager.DeleteSession(cookie.Value)
		}

		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (app *SSHManager) handleIndex(w http.ResponseWriter, r *http.Request) {
	status, _ := app.config.getSSHDStatus()

	// Try to read SSH server config from actual file
	var serverConfig SSHServerConfig
	var configError string
	sshConfig, err := app.config.ReadSSHServerConfig()
	if err != nil {
		// Config file doesn't exist or can't be read - provide diagnostics
		diag := app.config.DiagnoseSSHInstallation()
		configError = fmt.Sprintf("Cannot read SSH config: %v", err)

		// Create a default config for display purposes
		serverConfig = SSHServerConfig{
			Port:                   22,
			PermitRootLogin:        "prohibit-password",
			PasswordAuthentication: true,
			PubkeyAuthentication:   true,
			ConfigPath:             app.config.SSHConfigPath,
		}

		// Add diagnostic info to status
		status += fmt.Sprintf("\n\n❌ SSH Configuration Error: %s\n", configError)
		for _, suggestion := range diag.Suggestions {
			status += fmt.Sprintf("  • %s\n", suggestion)
		}
	} else {
		serverConfig = *sshConfig
	}

	data := struct {
		Server      SSHServerConfig
		KeyPairs    map[string]SSHKeyPair
		Status      string
		ConfigError string
	}{
		Server:      serverConfig,
		KeyPairs:    app.config.KeyPairs,
		Status:      status,
		ConfigError: configError,
	}

	tmpl := template.Must(template.New("index").Parse(indexTemplate))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error in handleIndex: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func (app *SSHManager) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			log.Printf("ERROR: Failed to parse form: %v", err)
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		// Collect validation errors
		var errors []string

		// Parse and validate port
		port := app.config.Server.Port
		if portStr := r.FormValue("port"); portStr != "" {
			if parsed, err := strconv.Atoi(portStr); err != nil {
				errors = append(errors, "SSH port must be a valid number")
			} else if parsed < 1 || parsed > 65535 {
				errors = append(errors, "SSH port must be between 1 and 65535")
			} else {
				port = parsed
			}
		}

		// Parse and validate web port
		webPort := app.config.Web.Port
		if webPortStr := r.FormValue("web_port"); webPortStr != "" {
			if parsed, err := strconv.Atoi(webPortStr); err != nil {
				errors = append(errors, "Web port must be a valid number")
			} else if parsed < 1 || parsed > 65535 {
				errors = append(errors, "Web port must be between 1 and 65535")
			} else {
				webPort = parsed
			}
		}

		// Validate other fields
		permitRootLogin := r.FormValue("permit_root_login")
		allowUsers := strings.TrimSpace(r.FormValue("allow_users"))
		denyUsers := strings.TrimSpace(r.FormValue("deny_users"))
		configPath := strings.TrimSpace(r.FormValue("config_path"))
		if configPath == "" {
			configPath = app.config.Server.ConfigPath
		}

		// Parse numeric fields
		maxAuthTries, _ := strconv.Atoi(r.FormValue("max_auth_tries"))
		if maxAuthTries < 1 {
			maxAuthTries = 6
		}

		maxSessions, _ := strconv.Atoi(r.FormValue("max_sessions"))
		if maxSessions < 1 {
			maxSessions = 10
		}

		clientAliveInterval, _ := strconv.Atoi(r.FormValue("client_alive_interval"))
		clientAliveCountMax, _ := strconv.Atoi(r.FormValue("client_alive_count_max"))
		if clientAliveCountMax < 1 {
			clientAliveCountMax = 3
		}

		loginGraceTime, _ := strconv.Atoi(r.FormValue("login_grace_time"))
		if loginGraceTime < 1 {
			loginGraceTime = 120
		}

		// Validate web password
		webPassword := strings.TrimSpace(r.FormValue("web_password"))
		keepExistingPassword := webPassword == ""
		if keepExistingPassword {
			webPassword = app.config.Web.Password
		} else {
			if len(webPassword) < 4 {
				errors = append(errors, "Web interface password must be at least 4 characters long")
			}
		}

		// If there are validation errors, show the form again with errors
		if len(errors) > 0 {
			data := struct {
				Server SSHServerConfig
				Web    WebConfig
				Errors []string
			}{
				Server: app.config.Server,
				Web:    app.config.Web,
				Errors: errors,
			}

			tmpl := template.Must(template.New("server").Parse(serverConfigTemplate))
			if err := tmpl.Execute(w, data); err != nil {
				log.Printf("Template execution error in handleServerConfig (POST with errors): %v", err)
				http.Error(w, "Template error", http.StatusInternalServerError)
			}
			return
		}

		// All validation passed, save the configuration
		app.config.Server.Port = port
		app.config.Server.PermitRootLogin = permitRootLogin
		app.config.Server.PasswordAuthentication = r.FormValue("password_authentication") == "true"
		app.config.Server.PubkeyAuthentication = r.FormValue("pubkey_authentication") == "true"
		app.config.Server.AllowUsers = allowUsers
		app.config.Server.DenyUsers = denyUsers
		app.config.Server.MaxAuthTries = maxAuthTries
		app.config.Server.MaxSessions = maxSessions
		app.config.Server.ClientAliveInterval = clientAliveInterval
		app.config.Server.ClientAliveCountMax = clientAliveCountMax
		app.config.Server.LoginGraceTime = loginGraceTime
		app.config.Server.ConfigPath = configPath

		// Parse other boolean fields
		app.config.Server.PrintMotd = r.FormValue("print_motd") == "true"
		app.config.Server.PrintLastLog = r.FormValue("print_last_log") == "true"
		app.config.Server.TCPKeepAlive = r.FormValue("tcp_keep_alive") == "true"
		app.config.Server.X11Forwarding = r.FormValue("x11_forwarding") == "true"
		app.config.Server.StrictModes = r.FormValue("strict_modes") == "true"
		app.config.Server.UsePAM = r.FormValue("use_pam") == "true"

		// Set string fields
		app.config.Server.AllowTcpForwarding = r.FormValue("allow_tcp_forwarding")
		app.config.Server.LogLevel = r.FormValue("log_level")

		// Update web configuration
		app.config.Web.Port = webPort

		// Hash the password if it's new and not already hashed
		if !keepExistingPassword {
			if !strings.HasPrefix(webPassword, "$2a$") && !strings.HasPrefix(webPassword, "$2b$") {
				if hashedPassword, err := HashPassword(webPassword); err == nil {
					app.config.Web.Password = hashedPassword
				} else {
					log.Printf("Error hashing password: %v", err)
					app.config.Web.Password = webPassword
				}
			} else {
				app.config.Web.Password = webPassword
			}
		}

		// Write SSH configuration if requested
		if r.FormValue("write_config") == "true" {
			backupDesc := "Configuration update via web interface"
			if err := app.config.WriteSSHServerConfigWithBackup(&app.config.Server, backupDesc); err != nil {
				http.Error(w, "Failed to write SSH config: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// Save the configuration
		if err := app.config.save(); err != nil {
			http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// GET request - show the form
	data := struct {
		Server SSHServerConfig
		Web    WebConfig
		Errors []string
	}{
		Server: app.config.Server,
		Web:    app.config.Web,
		Errors: nil,
	}

	tmpl := template.Must(template.New("server").Parse(serverConfigTemplate))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error in handleServerConfig (GET): %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func (app *SSHManager) handleBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Show backup management page
		bm := app.config.NewBackupManager()
		backups, err := bm.ListBackups()
		if err != nil {
			http.Error(w, "Failed to list backups: "+err.Error(), http.StatusInternalServerError)
			return
		}

		stats, err := bm.GetBackupStats()
		if err != nil {
			http.Error(w, "Failed to get backup stats: "+err.Error(), http.StatusInternalServerError)
			return
		}

		data := struct {
			Backups []BackupInfo
			Stats   map[string]interface{}
		}{
			Backups: backups,
			Stats:   stats,
		}

		tmpl := template.Must(template.New("backups").Parse(backupsTemplate))
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Template execution error in handleBackups: %v", err)
			http.Error(w, "Template error", http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == "POST" {
		r.ParseForm()
		action := r.FormValue("action")
		bm := app.config.NewBackupManager()

		switch action {
		case "create":
			description := strings.TrimSpace(r.FormValue("description"))
			if description == "" {
				description = "Manual backup"
			}

			backup, err := bm.CreateBackup(description, false)
			if err != nil {
				http.Error(w, "Failed to create backup: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Return JSON response for AJAX requests
			if r.Header.Get("Accept") == "application/json" {
				w.Header().Set("Content-Type", "application/json")
				response := map[string]interface{}{
					"success": true,
					"message": fmt.Sprintf("Backup created: %s", backup.Filename),
					"backup":  backup,
				}
				json.NewEncoder(w).Encode(response)
				return
			}

			http.Redirect(w, r, "/backups", http.StatusSeeOther)

		case "restore":
			backupPath := r.FormValue("backup_path")
			if backupPath == "" {
				http.Error(w, "Backup path is required", http.StatusBadRequest)
				return
			}

			if err := bm.RestoreBackup(backupPath); err != nil {
				http.Error(w, "Failed to restore backup: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Refresh the server config after restore
			app.config.refreshServerConfig()

			// Return JSON response for AJAX requests
			if r.Header.Get("Accept") == "application/json" {
				w.Header().Set("Content-Type", "application/json")
				response := map[string]interface{}{
					"success": true,
					"message": "Backup restored successfully",
				}
				json.NewEncoder(w).Encode(response)
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)

		case "delete":
			backupPath := r.FormValue("backup_path")
			if backupPath == "" {
				http.Error(w, "Backup path is required", http.StatusBadRequest)
				return
			}

			if err := os.Remove(backupPath); err != nil {
				http.Error(w, "Failed to delete backup: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Return JSON response for AJAX requests
			if r.Header.Get("Accept") == "application/json" {
				w.Header().Set("Content-Type", "application/json")
				response := map[string]interface{}{
					"success": true,
					"message": "Backup deleted successfully",
				}
				json.NewEncoder(w).Encode(response)
				return
			}

			http.Redirect(w, r, "/backups", http.StatusSeeOther)

		case "cleanup":
			if err := bm.CleanupOldBackups(); err != nil {
				http.Error(w, "Failed to cleanup backups: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Return JSON response for AJAX requests
			if r.Header.Get("Accept") == "application/json" {
				w.Header().Set("Content-Type", "application/json")
				response := map[string]interface{}{
					"success": true,
					"message": "Old backups cleaned up successfully",
				}
				json.NewEncoder(w).Encode(response)
				return
			}

			http.Redirect(w, r, "/backups", http.StatusSeeOther)

		default:
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		}
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (app *SSHManager) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	backupPath := r.URL.Query().Get("path")
	if backupPath == "" {
		http.Error(w, "Backup path is required", http.StatusBadRequest)
		return
	}

	// Security check: prevent path traversal attacks
	bm := app.config.NewBackupManager()

	// Clean and resolve the paths to prevent directory traversal
	cleanBackupPath := filepath.Clean(backupPath)
	cleanBackupDir := filepath.Clean(bm.BackupDir)

	// Convert to absolute paths for accurate comparison
	absBackupPath, err := filepath.Abs(cleanBackupPath)
	if err != nil {
		http.Error(w, "Invalid backup path", http.StatusBadRequest)
		return
	}

	absBackupDir, err := filepath.Abs(cleanBackupDir)
	if err != nil {
		http.Error(w, "Invalid backup directory", http.StatusInternalServerError)
		return
	}

	// Ensure the resolved path is within the backup directory
	if !strings.HasPrefix(absBackupPath, absBackupDir+string(os.PathSeparator)) && absBackupPath != absBackupDir {
		http.Error(w, "Access denied: path outside backup directory", http.StatusForbidden)
		return
	}

	// Check if file exists
	if _, err := os.Stat(absBackupPath); os.IsNotExist(err) {
		http.Error(w, "Backup file not found", http.StatusNotFound)
		return
	}

	// Additional security: ensure it's a regular file, not a directory or symlink
	if fileInfo, err := os.Stat(absBackupPath); err != nil {
		http.Error(w, "Cannot access backup file", http.StatusForbidden)
		return
	} else if !fileInfo.Mode().IsRegular() {
		http.Error(w, "Invalid file type", http.StatusForbidden)
		return
	}

	// Set headers for file download
	filename := filepath.Base(absBackupPath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "application/octet-stream")

	// Serve the file
	http.ServeFile(w, r, absBackupPath)
}

func (app *SSHManager) handleSSHControl(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		action := r.FormValue("action")

		var err error
		switch action {
		case "start":
			err = app.config.startSSHD()
		case "stop":
			err = app.config.stopSSHD()
		case "restart":
			err = app.config.restartSSHD()
		case "write_config":
			// First refresh the Server config from the actual file, then write it back with backup
			app.config.refreshServerConfig()
			err = app.config.WriteSSHServerConfigWithBackup(&app.config.Server, "Manual config write from SSH control")
		case "test_config":
			err = app.config.testSSHDConfig()
		default:
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		}

		if err != nil {
			http.Error(w, "Failed to "+action+" SSH daemon: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// For AJAX requests, return JSON response
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" || r.Header.Get("Accept") == "application/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "success", "action": action})
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *SSHManager) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := app.config.getSSHStats()
	if err != nil {
		data := struct {
			Error   string
			Running bool
		}{
			Error:   fmt.Sprintf("SSH statistics unavailable: %v", err),
			Running: false,
		}

		tmpl := template.Must(template.New("stats").Parse(statsTemplate))
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Template execution error in handleStats: %v", err)
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
		return
	}

	data := struct {
		Stats   *SSHStats
		Running bool
		Error   string
	}{
		Stats:   stats,
		Running: true,
		Error:   "",
	}

	tmpl := template.Must(template.New("stats").Parse(statsTemplate))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error in handleStats: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func (app *SSHManager) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	stats, err := app.config.getSSHStats()

	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		// Return empty stats when SSH is not running
		emptyStats := &SSHStats{
			ActiveConnections: 0,
			TotalConnections:  0,
			ConnectedUsers:    []ConnectedUser{},
		}
		if err := json.NewEncoder(w).Encode(emptyStats); err != nil {
			http.Error(w, "Failed to encode JSON: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Failed to encode JSON: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (app *SSHManager) handleAddKeyPair(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		name := strings.TrimSpace(r.FormValue("name"))
		keyType := strings.TrimSpace(r.FormValue("type"))
		comment := strings.TrimSpace(r.FormValue("comment"))

		if name == "" {
			http.Error(w, "Key pair name cannot be empty", http.StatusBadRequest)
			return
		}

		// Parse bits for RSA/ECDSA keys
		bits := 0
		if bitsStr := r.FormValue("bits"); bitsStr != "" {
			bits, _ = strconv.Atoi(bitsStr)
		}

		// Generate SSH key pair
		privateKeyPath, publicKey, err := generateSSHKeyPair(keyType, bits, comment)
		if err != nil {
			http.Error(w, "Failed to generate SSH key pair: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Add to configuration
		if err := app.config.addKeyPair(name); err != nil {
			http.Error(w, "Failed to add key pair: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Update key pair with generated data
		keyPair := app.config.KeyPairs[name]
		keyPair.Type = keyType
		keyPair.Bits = bits
		keyPair.Comment = comment
		keyPair.PublicKey = publicKey
		keyPair.PrivateKeyPath = privateKeyPath
		keyPair.Notes = strings.TrimSpace(r.FormValue("notes"))

		app.config.KeyPairs[name] = keyPair

		if err := app.config.save(); err != nil {
			http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.New("addkeypair").Parse(addKeyPairTemplate))
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Template execution error in handleAddKeyPair: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func (app *SSHManager) handleRemoveKeyPair(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		name := r.FormValue("name")

		if err := app.config.removeKeyPair(name); err != nil {
			http.Error(w, "Failed to remove key pair: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := app.config.save(); err != nil {
			http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *SSHManager) handleKeyQR(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Query().Get("name")
	if keyName == "" {
		http.Error(w, "Key name required", http.StatusBadRequest)
		return
	}

	keyType := r.URL.Query().Get("type") // "public", "private", "both"
	if keyType == "" {
		keyType = "public" // default to public key only
	}

	// Get the key pair to access both keys
	keyPair, exists := app.config.KeyPairs[keyName]
	if !exists {
		http.Error(w, "Key pair not found", http.StatusNotFound)
		return
	}

	// Read private key content
	var privateKeyContent string
	if keyType == "private" || keyType == "both" {
		content, err := os.ReadFile(keyPair.PrivateKeyPath)
		if err != nil {
			http.Error(w, "Failed to read private key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		privateKeyContent = string(content)
	}

	// Generate appropriate QR code(s)
	var qrBase64, publicQRCode, privateQRCode string
	var err error

	switch keyType {
	case "public":
		qrBase64, err = app.config.generatePublicKeyQR(keyName)
	case "private":
		qrBase64, err = app.config.generatePrivateKeyQR(keyName)
	case "both":
		// Generate both QR codes separately
		publicQRCode, err = app.config.generatePublicKeyQR(keyName)
		if err != nil {
			http.Error(w, "Failed to generate public QR code: "+err.Error(), http.StatusInternalServerError)
			return
		}
		privateQRCode, err = app.config.generatePrivateKeyQR(keyName)
		if err != nil {
			http.Error(w, "Failed to generate private QR code: "+err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Invalid key type. Use: public, private, or both", http.StatusBadRequest)
		return
	}

	if keyType != "both" && err != nil {
		http.Error(w, "Failed to generate QR code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		KeyName       string
		KeyType       string
		QRCode        string
		PublicQRCode  string
		PrivateQRCode string
		PublicKey     string
		PrivateKey    string
		HasPrivateKey bool
	}{
		KeyName:       keyName,
		KeyType:       keyType,
		QRCode:        qrBase64,
		PublicQRCode:  publicQRCode,
		PrivateQRCode: privateQRCode,
		PublicKey:     keyPair.PublicKey,
		PrivateKey:    privateKeyContent,
		HasPrivateKey: keyType == "private" || keyType == "both",
	}

	tmpl := template.Must(template.New("qr").Parse(qrTemplate))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error in handleKeyQR: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func (app *SSHManager) handleAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Return current config as JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(app.config)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
