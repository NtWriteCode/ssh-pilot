# 🚁 SSH Pilot

> **Ultra-lightweight SSH management with a clean web interface**

A single **native binary** that provides a modern web interface for managing SSH server configurations, client hosts, and key pairs. No Docker, no containers, no complexity - just drop the binary and run.

## ✨ Why This Exists

Managing SSH configurations traditionally requires editing config files manually, remembering complex syntax, and dealing with multiple tools. SSH Pilot gives you a clean web interface to handle all SSH management tasks in one place.

**Need command-line only?** → Use traditional SSH tools  
**Want visual management?** → You're in the right place  
**Want both convenience and power?** → SSH Pilot delivers

## 🚀 Quick Start

```bash
# Download and run
wget https://github.com/NtWriteCode/ssh-pilot/releases/latest/download/ssh-pilot
chmod +x ssh-pilot

# Start SSH Pilot
./ssh-pilot

# Open browser → http://localhost:8081
# Login: admin / admin (changeable in settings)
```

That's it. No configuration files required to get started.

## ⚡ Features

### 🔧 SSH Server Management
- **Visual Configuration** - Configure SSH daemon settings through web interface
- **Security Options** - Port, authentication methods, user restrictions
- **Config Generation** - Generate and write `sshd_config` files
- **Service Control** - Start, stop, restart SSH daemon
- **Configuration Testing** - Test SSH configuration before applying
- **Status Monitoring** - Real-time SSH daemon status and health

### 🌐 SSH Client Host Management
- **Host Database** - Store and manage SSH client configurations
- **Config Generation** - Generate SSH config entries for easy connection
- **Advanced Options** - Port forwarding, proxy commands, custom settings
- **Config Export** - Download client configurations as files
- **Connection Details** - Organize hosts with aliases and connection info

### 🔑 SSH Key Pair Management
- **Key Generation** - Generate SSH key pairs (RSA, Ed25519, ECDSA)
- **Key Organization** - Store and organize key information
- **QR Code Sharing** - Generate QR codes for easy key sharing
- **Multiple Types** - Support for various key sizes and comments
- **Secure Storage** - Keys stored in standard SSH locations

### 📊 Statistics & Monitoring
- **Active Connections** - View current SSH connections
- **User Sessions** - Monitor connected users and sessions
- **Health Checks** - SSH daemon status and health monitoring
- **Real-time Stats** - Connection statistics and usage data

## 📋 Requirements

- **Linux, macOS, or Windows** system
- **SSH daemon installed** (`openssh-server`)
- **Appropriate permissions** for SSH configuration management
- **systemctl** for service management (Linux)

No additional dependencies, databases, or services required.

## 🏗️ Installation

### Download Binary
```bash
# Intel/AMD (x64)
wget https://github.com/NtWriteCode/ssh-pilot/releases/latest/download/ssh-pilot-linux-amd64 -O ssh-pilot

# ARM64 (Pi 4, Apple Silicon servers)
wget https://github.com/NtWriteCode/ssh-pilot/releases/latest/download/ssh-pilot-linux-arm64 -O ssh-pilot

# ARM (Pi Zero, older Pi)
wget https://github.com/NtWriteCode/ssh-pilot/releases/latest/download/ssh-pilot-linux-arm -O ssh-pilot

# macOS Intel
wget https://github.com/NtWriteCode/ssh-pilot/releases/latest/download/ssh-pilot-darwin-amd64 -O ssh-pilot

# macOS Apple Silicon
wget https://github.com/NtWriteCode/ssh-pilot/releases/latest/download/ssh-pilot-darwin-arm64 -O ssh-pilot

chmod +x ssh-pilot
```

### Build from Source
```bash
git clone https://github.com/NtWriteCode/ssh-pilot.git
cd ssh-pilot
go build -o ssh-pilot .
```

## 🎯 Usage

### SSH Server Configuration

1. **Access Dashboard** → Navigate to Server Configuration
2. **Configure Settings**:
   - SSH port and web interface port
   - Authentication methods (password, public key)
   - User restrictions (allow/deny users)
   - Security settings (strict modes, timeouts)
   - Advanced options (forwarding, logging)

3. **Apply Changes**:
   - **Write Config** → Generate `sshd_config` file
   - **Test Config** → Validate settings before applying
   - **Restart SSH** → Apply changes to running service

### Managing Client Hosts

1. **Add Host** → Click "Add Client Host" from dashboard
2. **Configure Connection**:
   - Host alias and hostname/IP address
   - Username and port configuration
   - SSH key file path specification
   - Advanced options (forwarding, compression)

3. **Use Configuration**:
   - **View Config** → See generated SSH configuration
   - **Download Config** → Save as `.ssh/config` file

### SSH Key Management

1. **Generate Keys** → Click "Add Key Pair" from dashboard
2. **Choose Key Type**:
   - **Ed25519** (recommended) - Modern, secure, fast
   - **RSA** (compatible) - Widely supported legacy option
   - **ECDSA** (performance) - Good performance balance

3. **Key Management**:
   - Generated keys stored in `~/.ssh/` directory
   - **QR Code** feature for easy mobile sharing
   - Key information organized and searchable

## ⚙️ Configuration

- **Config file**: `ssh-pilot.json` (auto-created)
- **SSH configs**: Generated in standard SSH locations
- **Web port**: `8081` (use `PORT=8082` to change)
- **Session timeout**: `60 minutes` (configurable in web interface)

### Required Tools

SSH Pilot checks for these tools at startup:
- `ssh` - SSH client
- `sshd` - SSH daemon  
- `ssh-keygen` - Key generation
- `systemctl` - Service management

## 🔒 Security

**For local network use.** This tool manages SSH configurations and should be treated securely.

- ✅ **Bcrypt password hashing**
- ✅ **Session-based authentication**  
- ✅ **Rate limiting** (5 attempts = 15min block)
- ✅ **Secure cookie flags**
- ✅ **Input validation** and **XSS protection**
- ✅ **Configuration backups** before changes

### Security Best Practices
- **Change default password** immediately after first login
- **Use on trusted networks only** (localhost/LAN)
- **Run with appropriate permissions** (not root unless necessary)
- **Review configurations** before applying to production
- **Monitor SSH logs** for suspicious activity
- **Keep SSH keys secure** and rotate them regularly

## 🛠️ Troubleshooting

**Missing SSH Binaries:**
```bash
# Ubuntu/Debian
sudo apt install openssh-server openssh-client

# CentOS/RHEL
sudo yum install openssh-server openssh-clients
```

**Permission Denied Errors:**
```bash
# Run with appropriate permissions for SSH config management
sudo ./ssh-pilot

# Or ensure user has write access to SSH directories
```

**Configuration Test Failed:**
- Check SSH configuration syntax in generated files
- Verify file paths and permissions are correct
- Review SSH daemon logs: `journalctl -u ssh`

**Web Interface Not Accessible:**
```bash
# Check if port is available
netstat -tlnp | grep 8081

# Try different port
PORT=8082 ./ssh-pilot

# Check firewall settings
sudo ufw status
```

### Logs and Debugging

```bash
# Run with verbose output
./ssh-pilot 2>&1 | tee ssh-pilot.log

# Check SSH daemon logs
sudo journalctl -u ssh -f

# Monitor SSH connections
sudo journalctl -u ssh | grep "Accepted\|Failed"
```

## 🏗️ Architecture

```
ssh-pilot           (native binary)
├── Web Interface   (HTML + vanilla JS)
├── Session Auth    (secure cookies)
├── SSH Management  (sshd integration)
├── Config Generator (sshd_config + ssh_config)
├── Key Management  (ssh-keygen integration)
└── Service Control (systemctl integration)
```

**Files:**
- `main.go` - Application entry point and setup
- `config.go` - Configuration management and persistence
- `ssh.go` - SSH daemon operations and key management
- `handlers.go` - HTTP request handlers for web interface
- `templates.go` - HTML templates for web interface
- `qr.go` - QR code generation for key sharing

## 📊 API

SSH Pilot provides a simple JSON API when running in web mode:

- `GET /api` - Get current configuration (sanitized)
- `GET /api/stats` - Get SSH statistics and connection info
- `POST /ssh-control` - Control SSH daemon (start/stop/restart)

## 🚀 Roadmap

- [ ] **Multi-server management**
- [ ] **SSH certificate support**
- [ ] **Configuration templates**
- [ ] **Bulk operations**
- [ ] **Integration with cloud providers**
- [ ] **Advanced monitoring dashboards**

## 🤝 Contributing

This project prioritizes **simplicity and reliability**. PRs welcome for:
- Bug fixes and security improvements
- UI/UX enhancements
- Performance optimizations
- Documentation improvements

Please **avoid** adding:
- Heavy dependencies or complex frameworks
- Enterprise features that complicate core use cases
- Features that break the "single binary" principle

## 📝 License

MIT License - use it however you want.

---

**⭐ Star this repo if you find it useful!**

*Built with ❤️ for people who want simple, reliable SSH management without the complexity.* 