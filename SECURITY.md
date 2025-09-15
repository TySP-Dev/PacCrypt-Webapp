# PacCrypt Security Features 🔒

This document outlines the security enhancements added to PacCrypt, including setup instructions and configuration options.

## 🚀 New Security Features

### 1. Rate Limiting
- **API Endpoints**: Prevents abuse with configurable rate limits
- **Default Limits**:
  - `/api/algorithms`: 100 requests/minute
  - `/api/encrypt`, `/api/decrypt`: 30 requests/minute
  - `/api/generate-keypair`: 10 requests/minute
  - `/api/pacshare`: 10 requests/minute
  - Global default: 1000 requests/hour

### 2. Session Timeout
- **Admin Sessions**: Automatic timeout after configurable period (default: 30 minutes)
- **Security**: Sessions are cleared and require re-authentication
- **Logging**: Session timeouts are logged for audit purposes

### 3. File Virus Scanning
- **Integration**: ClamAV antivirus scanning before encryption
- **Automatic**: All uploaded files are scanned
- **Logging**: Scan results and virus detections are logged
- **Graceful Degradation**: If ClamAV is unavailable, scanning is skipped with warning

### 4. IP Whitelisting
- **Admin Access**: Restrict admin panel access to specific IP addresses
- **CIDR Support**: Supports both single IPs and CIDR notation (e.g., `192.168.1.0/24`)
- **Flexible**: Empty whitelist allows all IPs (default behavior)
- **Logging**: Unauthorized access attempts are logged

### 5. Enhanced Audit Logging
- **Encrypted Logs**: All admin actions are encrypted and logged
- **Comprehensive**: Login attempts, file operations, security events
- **IP Tracking**: Source IP addresses are logged for security monitoring

## 🛠️ Installation & Setup

### Prerequisites
```bash
# Update package lists
sudo apt update

# Install Python dependencies
pip install -r application_data/requirements.txt
```

### ClamAV Setup (Required for Virus Scanning)

#### Ubuntu/Debian:
```bash
# Install ClamAV
sudo apt install clamav clamav-daemon

# Update virus definitions
sudo freshclam

# Start ClamAV daemon
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon

# Verify installation
sudo systemctl status clamav-daemon
```

#### CentOS/RHEL:
```bash
# Install EPEL repository
sudo yum install epel-release

# Install ClamAV
sudo yum install clamav clamav-server clamav-update

# Update virus definitions
sudo freshclam

# Start services
sudo systemctl start clamd@scan
sudo systemctl enable clamd@scan
```

#### Manual Configuration:
If ClamAV fails to start, you may need to configure it manually:

```bash
# Edit configuration
sudo nano /etc/clamav/clamd.conf

# Remove or comment out the "Example" line
# Example

# Set socket permissions
sudo chown clamav:clamav /var/run/clamav/clamd.ctl
sudo chmod 666 /var/run/clamav/clamd.ctl

# Restart daemon
sudo systemctl restart clamav-daemon
```

### Testing ClamAV Integration
```bash
# Test if ClamAV is working
clamscan --version

# Test daemon connection
clamdscan --version

# Test with EICAR test file (harmless test virus)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
clamscan /tmp/eicar.txt
```

## ⚙️ Configuration

### Admin Settings Panel
Access the admin settings at `/admin-settings` to configure:

1. **Session Timeout**: Set admin session timeout (minutes)
2. **Virus Scanning**: Enable/disable ClamAV scanning
3. **IP Whitelist**: Configure allowed admin IP addresses
4. **File Limits**: Upload size and retention settings

### Manual Configuration
Edit `application_data/settings.json`:

```json
{
  "upload_folder": "pacshare",
  "max_file_age_days": 14,
  "max_file_size_bytes": 26843545600,
  "admin_ip_whitelist": [
    "192.168.1.100",
    "10.0.0.0/8",
    "127.0.0.1"
  ],
  "virus_scanning_enabled": true,
  "session_timeout_minutes": 30,
  "rate_limit_per_minute": 60,
  "rate_limit_per_hour": 1000
}
```

### IP Whitelist Examples
```json
"admin_ip_whitelist": [
  "127.0.0.1",              // Local access only
  "192.168.1.100",          // Specific IP
  "192.168.1.0/24",         // Local network
  "10.0.0.0/8",             // Private network range
  "203.0.113.0/24"          // Public IP range
]
```

## 🔍 Security Monitoring

### Log Files
- **Admin Logs**: `application_data/admin_logs.enc` (encrypted)
- **Application Logs**: Check console output for security events

### Key Events Logged
- Admin login/logout attempts
- Session timeouts
- IP whitelist violations
- Virus scan results
- File upload/download activities
- Rate limit violations

### Viewing Admin Logs
Access encrypted logs via the admin panel at `/admin-logs` or programmatically:

```python
# Example: View recent security events
key = load_admin_key()
cipher = Fernet(key)
with open('application_data/admin_logs.enc', 'rb') as f:
    for line in f:
        if line.strip():
            decrypted = cipher.decrypt(line.strip())
            print(decrypted.decode())
```

## 🚨 Security Best Practices

### 1. Regular Updates
```bash
# Update virus definitions
sudo freshclam

# Update Python dependencies
pip install --upgrade -r application_data/requirements.txt
```

### 2. Firewall Configuration
```bash
# UFW example - restrict admin access
sudo ufw allow from 192.168.1.0/24 to any port 5000
sudo ufw deny 5000
```

### 3. HTTPS Configuration
Always use HTTPS in production. Example nginx config:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;

    location /api/ {
        limit_req zone=api burst=5 nodelay;
        proxy_pass http://127.0.0.1:5000;
    }

    location /admin {
        # Additional admin restrictions
        allow 192.168.1.0/24;
        deny all;
        proxy_pass http://127.0.0.1:5000;
    }
}
```

### 4. Regular Security Audits
- Review admin logs regularly
- Monitor rate limit violations
- Check for unauthorized access attempts
- Verify virus scan effectiveness

## 🐛 Troubleshooting

### ClamAV Issues
```bash
# Check ClamAV status
sudo systemctl status clamav-daemon

# View ClamAV logs
sudo journalctl -u clamav-daemon

# Test socket connection
sudo -u clamav clamdscan --ping

# Manual socket creation
sudo mkdir -p /var/run/clamav
sudo chown clamav:clamav /var/run/clamav
```

### Rate Limiting Issues
- Check if requests are being properly limited
- Verify Flask-Limiter configuration
- Monitor application logs for rate limit errors

### Session Timeout Issues
- Verify session configuration in settings
- Check if `session.permanent = True` is set
- Ensure proper timezone handling

### IP Whitelist Issues
- Verify IP address format (CIDR notation)
- Check if client IP is correctly detected
- Consider proxy/load balancer IP forwarding

## 📋 Security Checklist

- [ ] ClamAV installed and running
- [ ] Virus definitions up to date
- [ ] Admin IP whitelist configured
- [ ] Session timeout configured
- [ ] Rate limiting tested
- [ ] HTTPS enabled in production
- [ ] Firewall rules configured
- [ ] Regular log monitoring set up
- [ ] Backup procedures for encrypted logs
- [ ] Security update schedule established

## 🔗 Related Documentation

- [Main README](README.md) - General installation and usage
- [API Documentation](API.md) - API endpoint details
- [Roadmap](ROADMAP.md) - Future security enhancements

---

**⚠️ Important Security Notes:**

1. **Default Configuration**: By default, IP whitelisting is disabled (empty list). Configure it for production use.

2. **ClamAV Dependency**: Virus scanning requires ClamAV. If not installed, scanning is skipped with warnings.

3. **Rate Limiting**: Default limits are conservative. Adjust based on your usage patterns.

4. **Log Encryption**: Admin logs are encrypted with the same key as admin credentials. Backup this key securely.

5. **Session Security**: Sessions use Flask's built-in session management. Consider Redis for distributed deployments.

For security questions or issues, please refer to the GitHub Issues page.