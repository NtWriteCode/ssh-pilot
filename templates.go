package main

const indexTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Pilot Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #007bff; padding-bottom: 10px; margin-bottom: 20px; }
        .header h1 { color: #333; margin: 0; }
        .nav-buttons { display: flex; gap: 10px; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }
        .btn-primary { background-color: #007bff; color: white; }
        .btn-secondary { background-color: #6c757d; color: white; }
        .btn-success { background-color: #28a745; color: white; }
        .btn-danger { background-color: #dc3545; color: white; }
        .btn-warning { background-color: #ffc107; color: black; }
        .btn-info { background-color: #17a2b8; color: white; }
        .btn:hover { opacity: 0.8; }
        .status-panel { background: #e7f3ff; border: 1px solid #007bff; border-radius: 4px; padding: 15px; margin-bottom: 20px; }
        .status-panel h3 { margin-top: 0; color: #004085; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
        .status-item { background: white; padding: 15px; border-radius: 4px; border: 1px solid #ddd; }
        .status-item h4 { margin-top: 0; color: #333; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .section h2 { color: #333; margin-top: 0; border-bottom: 1px solid #ddd; padding-bottom: 8px; }
        .status { padding: 10px; border-radius: 4px; margin: 10px 0; font-family: monospace; font-size: 12px; }
        .status.up { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.down { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .controls { margin: 10px 0; display: flex; gap: 5px; flex-wrap: wrap; }
        .controls form { display: inline; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; }
        .backup-notice { margin-top: 15px; padding: 10px; background-color: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 4px; }
        .backup-notice small { color: #1976d2; }
        .empty-state { text-align: center; padding: 40px; color: #666; }
        .empty-state h3 { color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚁 SSH Pilot</h1>
            <div class="nav-buttons">
                <a href="/server-config" class="btn btn-primary">Server Config</a>
                <a href="/hosts" class="btn btn-secondary">Client Hosts</a>
                <a href="/keys" class="btn btn-secondary">SSH Keys</a>
                <a href="/backups" class="btn btn-secondary">Backups</a>
                <form method="post" action="/logout" style="display: inline;">
                    <button type="submit" class="btn btn-warning">🚪 Logout</button>
                </form>
            </div>
        </div>

        <div class="status-panel">
            <h3>📊 SSH Server Overview</h3>
            <div class="status-grid">
                <div class="status-item">
                    <h4>🔧 Daemon Status</h4>
                    <div class="status {{if .Status}}up{{else}}down{{end}}">
                        <pre>{{.Status}}</pre>
                    </div>
                </div>
                <div class="status-item">
                    <h4>🌐 Server Configuration</h4>
                    <p><strong>SSH Port:</strong> {{.Server.Port}}</p>
                    <p><strong>Root Login:</strong> {{.Server.PermitRootLogin}}</p>
                    <p><strong>Password Auth:</strong> {{.Server.PasswordAuthentication}}</p>
                </div>
                <div class="status-item">
                    <h4>📈 Quick Stats</h4>
                    <p><strong>Client Hosts:</strong> {{len .Hosts}}</p>
                    <p><strong>SSH Keys:</strong> {{len .Keys}}</p>
                    <p><strong>Backups:</strong> {{len .Backups}}</p>
                </div>
                <div class="status-item">
                    <h4>⚡ Quick Actions</h4>
                    <div class="controls">
                        <form method="post" action="/ssh-control">
                            <input type="hidden" name="action" value="restart">
                            <button type="submit" class="btn btn-warning">🔄 Restart SSH</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🔧 SSH Daemon Control</h2>
            <div class="controls">
                <form method="post" action="/ssh-control">
                    <input type="hidden" name="action" value="start">
                    <button type="submit" class="btn btn-success">▶️ Start SSH</button>
                </form>
                <form method="post" action="/ssh-control">
                    <input type="hidden" name="action" value="stop">
                    <button type="submit" class="btn btn-danger">⏹️ Stop SSH</button>
                </form>
                <form method="post" action="/ssh-control">
                    <input type="hidden" name="action" value="restart">
                    <button type="submit" class="btn btn-warning">🔄 Restart SSH</button>
                </form>
                <form method="post" action="/ssh-control">
                    <input type="hidden" name="action" value="write_config">
                    <button type="submit" class="btn btn-secondary">💾 Write Config</button>
                </form>
                <form method="post" action="/ssh-control">
                    <input type="hidden" name="action" value="test_config">
                    <button type="submit" class="btn btn-info">🧪 Test Config</button>
                </form>
            </div>
            <div class="backup-notice">
                <small><strong>💡 Backup Protection:</strong> All configuration changes automatically create backups. Manage backups via the <a href="/backups">Backup Management</a> page.</small>
            </div>
        </div>

        <div class="section">
            <h2>⚙️ SSH Server Configuration</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Setting</th>
                            <th>Current Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td><strong>SSH Port</strong></td><td>{{.Server.Port}}</td></tr>
                        <tr><td><strong>Root Login</strong></td><td>{{.Server.PermitRootLogin}}</td></tr>
                        <tr><td><strong>Password Auth</strong></td><td>{{if .Server.PasswordAuthentication}}✅ Enabled{{else}}❌ Disabled{{end}}</td></tr>
                        <tr><td><strong>Public Key Auth</strong></td><td>{{if .Server.PubkeyAuthentication}}✅ Enabled{{else}}❌ Disabled{{end}}</td></tr>
                        <tr><td><strong>Max Auth Tries</strong></td><td>{{.Server.MaxAuthTries}}</td></tr>
                        <tr><td><strong>Max Sessions</strong></td><td>{{.Server.MaxSessions}}</td></tr>
                        <tr><td><strong>Log Level</strong></td><td>{{.Server.LogLevel}}</td></tr>
                        <tr><td><strong>Config Path</strong></td><td>{{.Server.ConfigPath}}</td></tr>
                        {{if .Server.AllowUsers}}<tr><td><strong>Allow Users</strong></td><td>{{.Server.AllowUsers}}</td></tr>{{end}}
                        {{if .Server.DenyUsers}}<tr><td><strong>Deny Users</strong></td><td>{{.Server.DenyUsers}}</td></tr>{{end}}
                    </tbody>
                </table>
            </div>
            <a href="/server-config" class="btn btn-primary">Configure Server</a>
            <a href="/stats" class="btn btn-info">View Statistics</a>
            <a href="/backups" class="btn btn-warning">🗄️ Manage Backups</a>
        </div>

        <div class="section">
            <h2>SSH Key Pairs</h2>
            {{if .KeyPairs}}
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Key Size</th>
                    <th>Comment</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
                {{range $name, $key := .KeyPairs}}
                <tr>
                    <td>
                        <strong>{{$name | html}}</strong>
                        {{if $key.Notes}}<br><small style="color: #666;">{{$key.Notes | html}}</small>{{end}}
                    </td>
                    <td>{{$key.Type | html}}</td>
                    <td>{{if gt $key.Bits 0}}{{$key.Bits}} bits{{else}}N/A{{end}}</td>
                    <td>{{if $key.Comment}}{{$key.Comment | html}}{{else}}<em>None</em>{{end}}</td>
                    <td>{{$key.CreatedAt | html}}</td>
                    <td>
                        <div class="qr-dropdown" style="position: relative; display: inline-block;">
                            <button class="btn btn-primary dropdown-toggle" onclick="toggleDropdown({{$name | js}})" style="cursor: pointer;">Share ▼</button>
                            <div id="dropdown-{{$name | html}}" class="dropdown-content" style="display: none; position: absolute; background-color: white; min-width: 160px; box-shadow: 0px 8px 16px rgba(0,0,0,0.2); z-index: 1; border-radius: 4px; border: 1px solid #ddd;">
                                <a href="/key-qr?name={{$name | urlquery}}&type=public" style="color: black; padding: 8px 12px; text-decoration: none; display: block;">🔓 Public Key</a>
                                <a href="/key-qr?name={{$name | urlquery}}&type=private" style="color: black; padding: 8px 12px; text-decoration: none; display: block;">🔐 Private Key</a>
                                <a href="/key-qr?name={{$name | urlquery}}&type=both" style="color: black; padding: 8px 12px; text-decoration: none; display: block;">🔗 Both Keys</a>
                            </div>
                        </div>
                        <form method="post" action="/remove-key-pair" style="display: inline;">
                            <input type="hidden" name="name" value="{{$name | html}}">
                            <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure?')">Remove</button>
                        </form>
                    </td>
                </tr>
                {{end}}
            </table>
            {{else}}
            <p>No SSH key pairs configured.</p>
            {{end}}
            <a href="/add-key-pair" class="btn btn-success">Add Key Pair</a>
        </div>
    </div>

    <script>
        function toggleDropdown(keyName) {
            // Escape the keyName for use in CSS selector
            var escapedKeyName = CSS.escape(keyName);
            var dropdown = document.getElementById("dropdown-" + escapedKeyName);
            // Close all other dropdowns first
            var allDropdowns = document.getElementsByClassName("dropdown-content");
            for (var i = 0; i < allDropdowns.length; i++) {
                if (allDropdowns[i].id !== "dropdown-" + escapedKeyName) {
                    allDropdowns[i].style.display = "none";
                }
            }
            // Toggle current dropdown
            if (dropdown && dropdown.style.display === "none") {
                dropdown.style.display = "block";
            } else if (dropdown) {
                dropdown.style.display = "none";
            }
        }

        // Close dropdown when clicking outside
        window.onclick = function(event) {
            if (!event.target.matches('.dropdown-toggle')) {
                var dropdowns = document.getElementsByClassName("dropdown-content");
                for (var i = 0; i < dropdowns.length; i++) {
                    dropdowns[i].style.display = "none";
                }
            }
        }
    </script>
</body>
</html>`

const serverConfigTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Configuration - SSH Pilot</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="number"], input[type="password"], select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background-color: #007bff; color: white; }
        .btn-secondary { background-color: #6c757d; color: white; }
        .btn:hover { opacity: 0.8; }
        .checkbox-group { margin: 15px 0; }
        .checkbox-group input[type="checkbox"] { margin-right: 10px; }
        .help-text { font-size: 12px; color: #666; margin-top: 5px; }
        .error-messages { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .error-messages h3 { margin-top: 0; color: #721c24; }
        .error-messages ul { margin: 10px 0; padding-left: 20px; }
        .error-messages li { margin: 5px 0; }
        .basic-section, .advanced-section { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .basic-section h3, .advanced-section h3 { margin-top: 0; color: #495057; }
        .basic-section { border-left: 4px solid #007bff; }
        .advanced-section { border-left: 4px solid #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SSH Server Configuration</h1>
        
        {{if .Errors}}
        <div class="error-messages">
            <h3>Please correct the following errors:</h3>
            <ul>
                {{range .Errors}}
                <li>{{.}}</li>
                {{end}}
            </ul>
        </div>
        {{end}}
        
        <form method="post">
            
            <div class="basic-section">
                <h3>🔧 Basic SSH Configuration</h3>
                
                <div class="form-group">
                    <label>SSH Port:</label>
                    <input type="number" name="port" value="{{.Server.Port}}" min="1" max="65535">
                    <div class="help-text">Port for SSH connections (default: 22)</div>
                </div>
                
                <div class="form-group">
                    <label>Web Interface Port:</label>
                    <input type="number" name="web_port" value="{{.Web.Port}}" min="1" max="65535">
                    <div class="help-text">Port for this web interface (default: 8081)</div>
                </div>
                
                <div class="form-group">
                    <label>Root Login:</label>
                    <select name="permit_root_login">
                        <option value="yes" {{if eq .Server.PermitRootLogin "yes"}}selected{{end}}>Yes</option>
                        <option value="no" {{if eq .Server.PermitRootLogin "no"}}selected{{end}}>No</option>
                        <option value="prohibit-password" {{if eq .Server.PermitRootLogin "prohibit-password"}}selected{{end}}>Prohibit Password</option>
                    </select>
                    <div class="help-text">Whether to allow root login and how</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="password_authentication" value="true" {{if .Server.PasswordAuthentication}}checked{{end}}>
                        Enable Password Authentication
                    </label>
                    <div class="help-text">Allow password-based authentication</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="pubkey_authentication" value="true" {{if .Server.PubkeyAuthentication}}checked{{end}}>
                        Enable Public Key Authentication
                    </label>
                    <div class="help-text">Allow public key based authentication (recommended)</div>
                </div>
                
                <div class="form-group">
                    <label>Web Interface Password:</label>
                    <input type="password" name="web_password" placeholder="Leave empty to keep current password">
                    <div class="help-text">Password for accessing this web interface</div>
                </div>
            </div>
            
            <div class="advanced-section">
                <h3>⚙️ Advanced Configuration</h3>
                
                <div class="form-group">
                    <label>Allow Users:</label>
                    <input type="text" name="allow_users" value="{{.Server.AllowUsers}}" placeholder="user1 user2 user3">
                    <div class="help-text">Space-separated list of allowed users (empty = all users)</div>
                </div>
                
                <div class="form-group">
                    <label>Deny Users:</label>
                    <input type="text" name="deny_users" value="{{.Server.DenyUsers}}" placeholder="baduser1 baduser2">
                    <div class="help-text">Space-separated list of denied users</div>
                </div>
                
                <div class="form-group">
                    <label>Max Auth Tries:</label>
                    <input type="number" name="max_auth_tries" value="{{.Server.MaxAuthTries}}" min="1" max="20">
                    <div class="help-text">Maximum authentication attempts per connection</div>
                </div>
                
                <div class="form-group">
                    <label>Max Sessions:</label>
                    <input type="number" name="max_sessions" value="{{.Server.MaxSessions}}" min="1" max="100">
                    <div class="help-text">Maximum number of concurrent SSH sessions</div>
                </div>
                
                <div class="form-group">
                    <label>Client Alive Interval:</label>
                    <input type="number" name="client_alive_interval" value="{{.Server.ClientAliveInterval}}" min="0" max="3600">
                    <div class="help-text">Seconds between keepalive messages (0 = disabled)</div>
                </div>
                
                <div class="form-group">
                    <label>Client Alive Count Max:</label>
                    <input type="number" name="client_alive_count_max" value="{{.Server.ClientAliveCountMax}}" min="1" max="10">
                    <div class="help-text">Max missed keepalive messages before disconnect</div>
                </div>
                
                <div class="form-group">
                    <label>Login Grace Time:</label>
                    <input type="number" name="login_grace_time" value="{{.Server.LoginGraceTime}}" min="30" max="600">
                    <div class="help-text">Time in seconds for user to authenticate</div>
                </div>
                
                <div class="form-group">
                    <label>Log Level:</label>
                    <select name="log_level">
                        <option value="QUIET" {{if eq .Server.LogLevel "QUIET"}}selected{{end}}>Quiet</option>
                        <option value="FATAL" {{if eq .Server.LogLevel "FATAL"}}selected{{end}}>Fatal</option>
                        <option value="ERROR" {{if eq .Server.LogLevel "ERROR"}}selected{{end}}>Error</option>
                        <option value="INFO" {{if eq .Server.LogLevel "INFO"}}selected{{end}}>Info</option>
                        <option value="VERBOSE" {{if eq .Server.LogLevel "VERBOSE"}}selected{{end}}>Verbose</option>
                        <option value="DEBUG" {{if eq .Server.LogLevel "DEBUG"}}selected{{end}}>Debug</option>
                    </select>
                    <div class="help-text">SSH daemon logging level</div>
                </div>
                
                <div class="form-group">
                    <label>Allow TCP Forwarding:</label>
                    <select name="allow_tcp_forwarding">
                        <option value="yes" {{if eq .Server.AllowTcpForwarding "yes"}}selected{{end}}>Yes</option>
                        <option value="no" {{if eq .Server.AllowTcpForwarding "no"}}selected{{end}}>No</option>
                        <option value="local" {{if eq .Server.AllowTcpForwarding "local"}}selected{{end}}>Local Only</option>
                        <option value="remote" {{if eq .Server.AllowTcpForwarding "remote"}}selected{{end}}>Remote Only</option>
                    </select>
                    <div class="help-text">Allow TCP port forwarding</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="x11_forwarding" value="true" {{if .Server.X11Forwarding}}checked{{end}}>
                        Enable X11 Forwarding
                    </label>
                    <div class="help-text">Allow X11 GUI application forwarding</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="strict_modes" value="true" {{if .Server.StrictModes}}checked{{end}}>
                        Enable Strict Modes
                    </label>
                    <div class="help-text">Check file permissions and ownership (recommended)</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="use_pam" value="true" {{if .Server.UsePAM}}checked{{end}}>
                        Use PAM
                    </label>
                    <div class="help-text">Use Pluggable Authentication Modules</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="print_motd" value="true" {{if .Server.PrintMotd}}checked{{end}}>
                        Print MOTD
                    </label>
                    <div class="help-text">Show message of the day on login</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="print_last_log" value="true" {{if .Server.PrintLastLog}}checked{{end}}>
                        Print Last Login
                    </label>
                    <div class="help-text">Show last login information</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="tcp_keep_alive" value="true" {{if .Server.TCPKeepAlive}}checked{{end}}>
                        TCP Keep Alive
                    </label>
                    <div class="help-text">Send TCP keepalive messages</div>
                </div>
                
                <div class="form-group">
                    <label>SSH Config File Path:</label>
                    <input type="text" name="config_path" value="{{.Server.ConfigPath}}">
                    <div class="help-text">Path to SSH daemon configuration file</div>
                </div>
                
                <div class="checkbox-group">
                    <label>
                        <input type="checkbox" name="write_config" value="true">
                        Write SSH configuration file after saving
                    </label>
                    <div class="help-text">Generate and write sshd_config file with these settings</div>
                </div>
            </div>
            
            <button type="submit" class="btn btn-primary">Save Configuration</button>
            <a href="/" class="btn btn-secondary">Cancel</a>
        </form>
    </div>
</body>
</html>`

const addKeyPairTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add SSH Key Pair - SSH Pilot</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="number"], select, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        textarea { height: 60px; resize: vertical; }
        .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background-color: #007bff; color: white; }
        .btn-secondary { background-color: #6c757d; color: white; }
        .btn:hover { opacity: 0.8; }
        .help-text { font-size: 12px; color: #666; margin-top: 5px; }
        .preset-buttons { margin: 10px 0; }
        .preset-btn { padding: 5px 10px; margin: 2px; border: 1px solid #007bff; background: white; color: #007bff; border-radius: 3px; cursor: pointer; font-size: 12px; }
        .preset-btn:hover { background: #007bff; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Add SSH Key Pair</h1>
        
        <form method="post">
            <div class="form-group">
                <label>Key Pair Name:</label>
                <input type="text" name="name" required placeholder="e.g., my-server-key, work-laptop">
                <div class="help-text">Unique name for this key pair</div>
            </div>
            
            <div class="form-group">
                <label>Key Type:</label>
                <select name="type" onchange="updateBitsField()">
                    <option value="ed25519">Ed25519 (recommended)</option>
                    <option value="rsa">RSA</option>
                    <option value="ecdsa">ECDSA</option>
                </select>
                <div class="preset-buttons">
                    <button type="button" class="preset-btn" onclick="setKeyType('ed25519')">🔐 Modern (Ed25519)</button>
                    <button type="button" class="preset-btn" onclick="setKeyType('rsa')">🔑 Compatible (RSA)</button>
                    <button type="button" class="preset-btn" onclick="setKeyType('ecdsa')">⚡ Fast (ECDSA)</button>
                </div>
                <div class="help-text">Ed25519 is recommended for new keys (secure, fast, small)</div>
            </div>
            
            <div class="form-group" id="bits-group" style="display: none;">
                <label>Key Size (bits):</label>
                <input type="number" name="bits" value="4096" min="1024" max="8192">
                <div class="help-text">Key size in bits (RSA: 2048-4096, ECDSA: 256-521)</div>
            </div>
            
            <div class="form-group">
                <label>Comment:</label>
                <input type="text" name="comment" placeholder="e.g., user@hostname, purpose of key">
                <div class="help-text">Optional comment to identify the key</div>
            </div>
            
            <div class="form-group">
                <label>Notes:</label>
                <textarea name="notes" placeholder="e.g., Key for production servers, Personal development key, etc."></textarea>
                <div class="help-text">Optional notes about this key pair</div>
            </div>
            
            <button type="submit" class="btn btn-primary">Generate Key Pair</button>
            <a href="/" class="btn btn-secondary">Cancel</a>
        </form>
    </div>
    
    <script>
        function setKeyType(type) {
            document.querySelector('select[name="type"]').value = type;
            updateBitsField();
        }
        
        function updateBitsField() {
            const keyType = document.querySelector('select[name="type"]').value;
            const bitsGroup = document.getElementById('bits-group');
            const bitsInput = document.querySelector('input[name="bits"]');
            
            if (keyType === 'ed25519') {
                bitsGroup.style.display = 'none';
                bitsInput.value = '';
            } else {
                bitsGroup.style.display = 'block';
                if (keyType === 'rsa') {
                    bitsInput.value = '4096';
                    bitsInput.min = '2048';
                    bitsInput.max = '8192';
                } else if (keyType === 'ecdsa') {
                    bitsInput.value = '256';
                    bitsInput.min = '256';
                    bitsInput.max = '521';
                }
            }
        }
        
        // Initialize on page load
        updateBitsField();
    </script>
</body>
</html>`

const qrTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QR Code for {{.KeyName}} - SSH Pilot</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; text-align: center; }
        .qr-section { text-align: center; margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .qr-options { margin: 20px 0; text-align: center; }
        .qr-options a { margin: 0 10px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; display: inline-block; }
        .qr-options a.active { background: #0056b3; }
        .qr-options a:hover { background: #0056b3; }
        .key-display { margin: 20px 0; }
        .key-container { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; margin: 10px 0; }
        .key-header { background: #e9ecef; padding: 10px; border-bottom: 1px solid #dee2e6; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
        .key-content { padding: 10px; font-family: monospace; font-size: 12px; word-break: break-all; max-height: 200px; overflow-y: auto; white-space: pre-wrap; }
        .copy-btn { padding: 5px 10px; background: #28a745; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 11px; }
        .copy-btn:hover { background: #218838; }
        .copy-btn.copied { background: #6c757d; }
        .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-secondary { background-color: #6c757d; color: white; }
        .btn:hover { opacity: 0.8; }
        .instructions { text-align: left; margin: 20px 0; padding: 15px; background: #e7f3ff; border-left: 4px solid #007bff; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; color: #856404; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SSH Key: {{.KeyName | html}}</h1>
        
        <div class="qr-options">
            <strong>Share Options:</strong><br><br>
            <a href="/key-qr?name={{.KeyName | urlquery}}&type=public" {{if eq .KeyType "public"}}class="active"{{end}}>Public Key</a>
            <a href="/key-qr?name={{.KeyName | urlquery}}&type=private" {{if eq .KeyType "private"}}class="active"{{end}}>Private Key</a>
            <a href="/key-qr?name={{.KeyName | urlquery}}&type=both" {{if eq .KeyType "both"}}class="active"{{end}}>Both Keys</a>
        </div>

        {{if eq .KeyType "both"}}
        <div class="qr-section">
            <h3>Separate QR Codes for Both Keys</h3>
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap; gap: 20px;">
                <div style="text-align: center;">
                    <h4>🔓 Public Key QR</h4>
                    <img src="data:image/png;base64,{{.PublicQRCode}}" alt="Public Key QR Code" style="max-width: 100%; height: auto;">
                </div>
                <div style="text-align: center;">
                    <h4>🔐 Private Key QR</h4>
                    <img src="data:image/png;base64,{{.PrivateQRCode}}" alt="Private Key QR Code" style="max-width: 100%; height: auto;">
                </div>
            </div>
        </div>
        {{else}}
        <div class="qr-section">
            <h3>{{if eq .KeyType "public"}}Public Key QR Code{{else}}Private Key QR Code{{end}}</h3>
            <img src="data:image/png;base64,{{.QRCode}}" alt="QR Code for {{.KeyName | html}}" style="max-width: 100%; height: auto;">
        </div>
        {{end}}

        <div class="key-display">
            <h3>Copyable Keys</h3>
            
            {{if ne .KeyType "private"}}
            <div class="key-container">
                <div class="key-header">
                    <span>🔓 Public Key</span>
                    <button class="copy-btn" onclick="copyToClipboard('public-key', this)">Copy</button>
                </div>
                <div class="key-content" id="public-key">{{.PublicKey}}</div>
            </div>
            {{end}}

            {{if .HasPrivateKey}}
            <div class="key-container">
                <div class="key-header">
                    <span>🔐 Private Key</span>
                    <button class="copy-btn" onclick="copyToClipboard('private-key', this)">Copy</button>
                </div>
                <div class="key-content" id="private-key">{{.PrivateKey}}</div>
            </div>
            
            <div class="warning">
                <strong>⚠️ Security Warning:</strong> The private key is sensitive information. Only share it securely and with trusted systems. Never expose private keys in public places.
            </div>
            {{end}}
        </div>
        
        <div class="instructions">
            <h3>Usage Instructions</h3>
            {{if eq .KeyType "public"}}
            <ul>
                <li>The public key can be safely shared and added to <code>~/.ssh/authorized_keys</code> on servers</li>
                <li>Use the QR code to quickly transfer the public key to mobile devices</li>
                <li>Copy the text version for easy pasting into configuration files</li>
            </ul>
            {{else if eq .KeyType "private"}}
            <ul>
                <li><strong>Keep the private key secure!</strong> This allows authentication as this identity</li>
                <li>Save the private key as a file (e.g., <code>~/.ssh/{{.KeyName | html}}</code>) with permissions 600</li>
                <li>Use with SSH: <code>ssh -i ~/.ssh/{{.KeyName | html}} user@server</code></li>
            </ul>
                         {{else}}
             <ul>
                 <li>Two separate QR codes are provided - one for the public key and one for the private key</li>
                 <li>Scan both QR codes to quickly set up complete SSH access on a new device</li>
                 <li>The public key QR can be shared safely for server authorization</li>
                 <li>The private key QR should be handled securely and only used on trusted devices</li>
                 <li><strong>Keep the private key QR secure!</strong> It provides authentication access</li>
             </ul>
             {{end}}
        </div>
        
        <div style="margin-top: 30px; text-align: center;">
            <a href="/" class="btn btn-secondary">Back to Dashboard</a>
        </div>
    </div>

    <script>
        function copyToClipboard(elementId, button) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            navigator.clipboard.writeText(text).then(function() {
                button.textContent = 'Copied!';
                button.classList.add('copied');
                setTimeout(function() {
                    button.textContent = 'Copy';
                    button.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                button.textContent = 'Copied!';
                button.classList.add('copied');
                setTimeout(function() {
                    button.textContent = 'Copy';
                    button.classList.remove('copied');
                }, 2000);
            });
        }
    </script>
</body>
</html>`

const loginTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SSH Pilot</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { max-width: 400px; width: 100%; background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); padding: 2rem; }
        h1 { text-align: center; color: #333; margin-bottom: 2rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
        input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #007bff; box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25); }
        .btn { width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 1rem; }
        .btn:hover { background: #0056b3; }
        .remember-me { display: flex; align-items: center; margin: 1rem 0; }
        .remember-me input { margin-right: 0.5rem; }
        .error { color: #dc3545; text-align: center; margin-bottom: 1rem; padding: 0.5rem; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; }
        .blocked { color: #856404; text-align: center; margin-bottom: 1rem; padding: 0.5rem; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; }
        .security-notice { background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 1rem; margin-bottom: 1rem; color: #856404; }
        .security-notice h3 { margin-top: 0; color: #856404; }
        .security-notice ul { margin: 0.5rem 0; padding-left: 1.5rem; }
        .security-notice li { margin-bottom: 0.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚁 SSH Pilot</h1>
        
        {{if .UsingDefaultPassword}}
        <div class="security-notice">
            <h3>⚠️ Critical Security Notice</h3>
            <p><strong>Default credentials detected!</strong> You must change the password on first login.</p>
            <ul>
                <li>This tool manages your SSH keys and server configuration</li>
                <li>Unauthorized access could compromise your SSH security</li>
                <li>Never expose this service to the internet</li>
                <li>Run only on trusted local networks</li>
            </ul>
        </div>
        {{else}}
        <div class="security-notice">
            <h3>⚠️ Security Notice</h3>
            <ul>
                <li>This tool manages your SSH keys and server configuration</li>
                <li>Never expose this service to the internet</li>
                <li>Run only on trusted local networks</li>
                <li>Use on-demand for maximum security</li>
            </ul>
        </div>
        {{end}}

        <form id="loginForm" action="/login" method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="admin" readonly>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" placeholder="Enter default password 'admin'" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            var username = document.getElementById('username').value;
            var password = document.getElementById('password').value;
            
            if (!username || !password) {
                e.preventDefault();
                alert('Please enter both username and password.');
            }
        });
    </script>
</body>
</html>`

const changePasswordTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{if .Forced}}Required Password Change{{else}}Change Password{{end}} - SSH Pilot</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { max-width: 600px; width: 100%; background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); padding: 2rem; }
        h1 { text-align: center; color: #333; margin-bottom: 2rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: bold; }
        input[type="password"] { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
        input[type="password"]:focus { outline: none; border-color: #007bff; box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25); }
        .btn { width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 1rem; }
        .btn:hover { background: #0056b3; }
        .security-warning { background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; padding: 1.5rem; margin-bottom: 2rem; color: #721c24; }
        .security-warning h3 { margin-top: 0; color: #721c24; }
        .security-warning ul { margin: 1rem 0; padding-left: 1.5rem; }
        .security-warning li { margin-bottom: 0.5rem; font-weight: 500; }
        .acknowledgment { background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 1rem; margin: 1rem 0; color: #856404; }
        .acknowledgment label { display: flex; align-items: flex-start; cursor: pointer; font-weight: normal; }
        .acknowledgment input[type="checkbox"] { margin-right: 0.5rem; margin-top: 0.25rem; }
        .password-requirements { background: #e7f3ff; border: 1px solid #007bff; border-radius: 4px; padding: 1rem; margin-bottom: 1rem; color: #004085; }
        .password-requirements h4 { margin-top: 0; }
        .password-requirements ul { margin: 0.5rem 0; padding-left: 1.5rem; }
        {{if .Forced}}.forced-notice { background: #dc3545; color: white; padding: 1rem; margin-bottom: 2rem; border-radius: 4px; text-align: center; font-weight: bold; }{{end}}
    </style>
</head>
<body>
    <div class="container">
        <h1>{{if .Forced}}🚨 Required Password Change{{else}}🔐 Change Password{{end}}</h1>
        
        {{if .Forced}}
        <div class="forced-notice">
            You must change the default password before accessing SSH Pilot!
        </div>
        {{end}}
        
        <div class="security-warning">
            <h3>🛡️ Critical Security Information</h3>
            <p><strong>Please read and understand these important security considerations:</strong></p>
            <ul>
                <li><strong>Not Battle-Tested:</strong> SSH Pilot is a convenience tool, not a hardened security application</li>
                <li><strong>SSH Key Access Risk:</strong> If compromised, an attacker could gain access to your SSH private keys</li>
                <li><strong>Network Exposure:</strong> NEVER expose this service to the internet or untrusted networks</li>
                <li><strong>Local Use Only:</strong> Run only on trusted local networks (localhost/LAN)</li>
                <li><strong>On-Demand Usage:</strong> For maximum security, run only when needed, not 24/7</li>
                <li><strong>Backup Your Keys:</strong> Always maintain secure backups of your SSH keys outside this tool</li>
            </ul>
        </div>

        <div class="password-requirements">
            <h4>Password Requirements:</h4>
            <ul>
                <li>Minimum 8 characters long</li>
                <li>Cannot be "admin" or other common passwords</li>
                <li>Choose a strong, unique password</li>
                <li>Consider using a password manager</li>
            </ul>
        </div>

        <form action="/change-password{{if .Forced}}?force=true{{end}}" method="post">
            <div class="form-group">
                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required minlength="8">
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm New Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
            </div>
            
            <div class="acknowledgment">
                <label>
                    <input type="checkbox" name="security_acknowledged" required>
                    <span>I understand and acknowledge the security risks outlined above. I will not expose this service to the internet and will use it responsibly on trusted networks only.</span>
                </label>
            </div>
            
            <button type="submit" class="btn">{{if .Forced}}Set New Password & Continue{{else}}Change Password{{end}}</button>
        </form>
    </div>

    <script>
        document.querySelector('form').addEventListener('submit', function(e) {
            var newPassword = document.getElementById('new_password').value;
            var confirmPassword = document.getElementById('confirm_password').value;
            var acknowledged = document.querySelector('input[name="security_acknowledged"]').checked;
            
            if (newPassword !== confirmPassword) {
                e.preventDefault();
                alert('Passwords do not match!');
                return;
            }
            
            if (newPassword.length < 8) {
                e.preventDefault();
                alert('Password must be at least 8 characters long!');
                return;
            }
            
            if (newPassword.toLowerCase() === 'admin') {
                e.preventDefault();
                alert('Cannot use "admin" as password!');
                return;
            }
            
            if (!acknowledged) {
                e.preventDefault();
                alert('You must acknowledge the security warnings to continue!');
                return;
            }
        });
    </script>
</body>
</html>`

const statsTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Statistics - SSH Pilot</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; text-align: center; }
        .stat-card h3 { margin: 0 0 10px 0; color: #495057; font-size: 14px; text-transform: uppercase; }
        .stat-value { font-size: 28px; font-weight: bold; color: #007bff; margin: 10px 0; }
        .stat-label { font-size: 12px; color: #6c757d; }
        .active-indicator { color: #28a745; }
        .inactive-indicator { color: #dc3545; }
        .data-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .data-table th, .data-table td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        .data-table th { background-color: #f8f9fa; font-weight: bold; }
        .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background-color: #007bff; color: white; }
        .btn-secondary { background-color: #6c757d; color: white; }
        .btn:hover { opacity: 0.8; }
        .error-message { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 4px; margin: 20px 0; text-align: center; }
        .refresh-info { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 10px; border-radius: 4px; margin: 20px 0; text-align: center; font-size: 12px; }
        .auto-refresh { margin: 20px 0; text-align: center; }
        .auto-refresh input { margin: 0 5px; }
        pre { font-size: 11px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SSH Statistics</h1>
        
        {{if not .Running}}
            <div class="error-message">
                <h3>Statistics Unavailable</h3>
                <p>{{.Error}}</p>
                <p>Make sure SSH daemon is running and you have the necessary permissions.</p>
            </div>
        {{else}}
            <div class="refresh-info">
                📊 Statistics updated in real-time • Last refresh: <span id="lastRefresh">now</span>
            </div>
            
            <div class="auto-refresh">
                <label>
                    <input type="checkbox" id="autoRefresh" checked onchange="toggleAutoRefresh()">
                    Auto-refresh every 10 seconds
                </label>
            </div>
            
            <!-- Overview Statistics -->
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Active Connections</h3>
                    <div class="stat-value {{if gt .Stats.ActiveConnections 0}}active-indicator{{else}}inactive-indicator{{end}}">{{.Stats.ActiveConnections}}</div>
                    <div class="stat-label">Currently Connected</div>
                </div>
                
                <div class="stat-card">
                    <h3>Total Connections</h3>
                    <div class="stat-value">{{.Stats.TotalConnections}}</div>
                    <div class="stat-label">All Time</div>
                </div>
                
                <div class="stat-card">
                    <h3>Failed Attempts</h3>
                    <div class="stat-value {{if gt .Stats.FailedConnections 0}}inactive-indicator{{else}}active-indicator{{end}}">{{.Stats.FailedConnections}}</div>
                    <div class="stat-label">Authentication Failures</div>
                </div>
            </div>
            
            <!-- SSH Daemon Status -->
            <h2>SSH Daemon Status</h2>
            <div class="status">
                <pre>{{.Stats.SSHDStatus}}</pre>
            </div>
            
            <!-- Connected Users Table -->
            <h2>Currently Connected Users</h2>
            {{if .Stats.ConnectedUsers}}
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Terminal</th>
                            <th>Host</th>
                            <th>Started</th>
                            <th>Idle</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Stats.ConnectedUsers}}
                        <tr>
                            <td><strong>{{.User}}</strong></td>
                            <td>{{.Terminal}}</td>
                            <td>{{if .Host}}{{.Host}}{{else}}-{{end}}</td>
                            <td>{{.Started.Format "2006-01-02 15:04:05"}}</td>
                            <td>{{if .Idle}}{{.Idle}}{{else}}-{{end}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            {{else}}
                <div class="error-message">
                    <p>No active SSH connections found.</p>
                </div>
            {{end}}
        {{end}}
        
        <div style="text-align: center; margin-top: 40px;">
            <a href="/" class="btn btn-secondary">Back to Dashboard</a>
            <button onclick="refreshStats()" class="btn btn-primary">Refresh Now</button>
        </div>
    </div>

    <script>
        let autoRefreshInterval;
        
        function toggleAutoRefresh() {
            const checkbox = document.getElementById('autoRefresh');
            if (checkbox.checked) {
                autoRefreshInterval = setInterval(refreshStats, 10000);
            } else {
                clearInterval(autoRefreshInterval);
            }
        }
        
        function refreshStats() {
            document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();
            location.reload();
        }
        
        // Start auto-refresh by default
        toggleAutoRefresh();
        
        // Update last refresh time
        document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();
    </script>
</body>
</html>`

const backupsTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Configuration Backups - SSH Pilot</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 30px;
        }
        
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        
        .stat-card h3 {
            margin: 0 0 10px 0;
            color: #667eea;
            font-size: 1.1em;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        .actions-bar {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-warning {
            background: #ffc107;
            color: #212529;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .data-table th,
        .data-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        
        .data-table th {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        
        .data-table tr:hover {
            background-color: #f8f9fa;
        }
        
        .backup-actions {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }
        
        .backup-actions .btn {
            padding: 6px 12px;
            font-size: 12px;
        }
        
        .backup-type {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }
        
        .backup-automatic {
            background: #e3f2fd;
            color: #1976d2;
        }
        
        .backup-manual {
            background: #f3e5f5;
            color: #7b1fa2;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #333;
        }
        
        .form-control {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-info {
            background: #e3f2fd;
            color: #1976d2;
            border-left: 4px solid #2196f3;
        }
        
        .alert-warning {
            background: #fff3cd;
            color: #856404;
            border-left: 4px solid #ffc107;
        }
        
        .file-size {
            color: #666;
            font-size: 0.9em;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 30px;
            border-radius: 10px;
            width: 90%;
            max-width: 500px;
            text-align: center;
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: black;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🗄️ SSH Configuration Backups</h1>
        
        <!-- Backup Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Backups</h3>
                <div class="stat-value">{{.Stats.total_backups}}</div>
                <div class="stat-label">Files Available</div>
            </div>
            
            <div class="stat-card">
                <h3>Automatic</h3>
                <div class="stat-value">{{.Stats.automatic_count}}</div>
                <div class="stat-label">System Generated</div>
            </div>
            
            <div class="stat-card">
                <h3>Manual</h3>
                <div class="stat-value">{{.Stats.manual_count}}</div>
                <div class="stat-label">User Created</div>
            </div>
            
            <div class="stat-card">
                <h3>Storage Used</h3>
                <div class="stat-value">{{printf "%.1f" .Stats.total_size_mb}}MB</div>
                <div class="stat-label">Disk Space</div>
            </div>
        </div>
        
        <!-- Actions Bar -->
        <div class="actions-bar">
            <button onclick="showCreateBackupModal()" class="btn btn-primary">
                📁 Create Manual Backup
            </button>
            
            <form method="post" style="display: inline;">
                <input type="hidden" name="action" value="cleanup">
                <button type="submit" class="btn btn-warning" onclick="return confirm('This will delete old backups according to retention policy. Continue?')">
                    🧹 Cleanup Old Backups
                </button>
            </form>
            
            <a href="/" class="btn btn-secondary">
                ← Back to Dashboard
            </a>
        </div>
        
        {{if eq .Stats.total_backups 0}}
            <div class="alert alert-info">
                <p><strong>No backups found.</strong></p>
                <p>SSH configuration backups will be created automatically when you make changes, or you can create manual backups using the button above.</p>
            </div>
        {{else}}
            <!-- Backups Table -->
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Backup File</th>
                        <th>Description</th>
                        <th>Type</th>
                        <th>Created</th>
                        <th>Size</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Backups}}
                    <tr>
                        <td>
                            <strong>{{.Filename}}</strong>
                            <br>
                            <small class="file-size">{{.Path}}</small>
                        </td>
                        <td>{{.Description}}</td>
                        <td>
                            <span class="backup-type {{if .IsAutomatic}}backup-automatic{{else}}backup-manual{{end}}">
                                {{if .IsAutomatic}}Automatic{{else}}Manual{{end}}
                            </span>
                        </td>
                        <td>{{.CreatedAt.Format "2006-01-02 15:04:05"}}</td>
                        <td class="file-size">{{.Size}} bytes</td>
                        <td>
                            <div class="backup-actions">
                                <button onclick="restoreBackup('{{.Path}}')" class="btn btn-success" title="Restore this backup">
                                    🔄 Restore
                                </button>
                                
                                <a href="/download-backup?path={{.Path}}" class="btn btn-primary" title="Download backup file">
                                    💾 Download
                                </a>
                                
                                <button onclick="deleteBackup('{{.Path}}')" class="btn btn-danger" title="Delete this backup">
                                    🗑️ Delete
                                </button>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        {{end}}
        
        {{if gt .Stats.total_backups 5}}
            <div class="alert alert-warning">
                <p><strong>Backup Management:</strong> You have {{.Stats.total_backups}} backups using {{printf "%.1f" .Stats.total_size_mb}}MB of disk space.</p>
                <p>Consider running cleanup to remove old backups according to the retention policy (keeps 10 most recent, deletes backups older than 30 days).</p>
            </div>
        {{end}}
    </div>
    
    <!-- Create Backup Modal -->
    <div id="createBackupModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="hideCreateBackupModal()">&times;</span>
            <h2>Create Manual Backup</h2>
            <form method="post" id="createBackupForm">
                <input type="hidden" name="action" value="create">
                <div class="form-group">
                    <label for="description">Backup Description:</label>
                    <input type="text" id="description" name="description" class="form-control" 
                           placeholder="e.g., Before security update" maxlength="50">
                    <small>Optional: Describe why you're creating this backup</small>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <button type="submit" class="btn btn-primary">Create Backup</button>
                    <button type="button" onclick="hideCreateBackupModal()" class="btn btn-secondary">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function showCreateBackupModal() {
            document.getElementById('createBackupModal').style.display = 'block';
        }
        
        function hideCreateBackupModal() {
            document.getElementById('createBackupModal').style.display = 'none';
        }
        
        function restoreBackup(backupPath) {
            if (!confirm('This will replace the current SSH configuration with the selected backup.\\n\\nA backup of the current configuration will be created before restoring.\\n\\nContinue?')) {
                return;
            }
            
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = '<input type="hidden" name="action" value="restore">' +
                '<input type="hidden" name="backup_path" value="' + backupPath + '">';
            document.body.appendChild(form);
            form.submit();
        }
        
        function deleteBackup(backupPath) {
            const filename = backupPath.split('/').pop();
            if (!confirm('Are you sure you want to delete the backup "' + filename + '"?\\n\\nThis action cannot be undone.')) {
                return;
            }
            
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = '<input type="hidden" name="action" value="delete">' +
                '<input type="hidden" name="backup_path" value="' + backupPath + '">';
            document.body.appendChild(form);
            form.submit();
        }
        
        // Close modal when clicking outside of it
        window.onclick = function(event) {
            const modal = document.getElementById('createBackupModal');
            if (event.target == modal) {
                hideCreateBackupModal();
            }
        }
    </script>
</body>
</html>`
