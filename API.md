# PacCrypt API Documentation 🔐

> [!IMPORTANT]
> This document is fully AI generated, pending my review.
> It is only here so I can push to alpha.
> Next push will contain human oversite on the documentation.

This document provides AI slop documentation for the PacCrypt REST API, covering all endpoints for encryption, decryption, file sharing, and administrative operations.

## 🌐 Base URLs

- **Official Instance**: `https://paccrypt.unnaturalll.dev`
- **Self-hosted**: `http://YOUR_SERVER_IP:5000` or `https://your-domain.com`

## 📋 Table of Contents

- [Authentication](#authentication)
- [Encryption Operations](#encryption-operations)
- [PacShare File Sharing](#pacshare-file-sharing)
- [Administrative Endpoints](#administrative-endpoints)
- [Error Handling](#error-handling)
- [Examples](#examples)

---

## 🔑 Authentication

Most API endpoints are **public** and don't require authentication. Admin endpoints require session-based authentication.

### Admin Authentication Flow

1. **Setup Admin Account** (first-time only)
   ```
   POST /admin-setup
   ```

2. **Login**
   ```
   POST /admin-login
   ```

3. **Access Admin Endpoints** (with session)

---

## 🔐 Encryption Operations

### 1. Get Available Algorithms

Get list of supported encryption algorithms and their capabilities.

**Endpoint**: `GET /api/algorithms`

**Response**:
```json
{
  "algorithms": {
    "aes_gcm": {
      "name": "AES-GCM",
      "description": "AES-256 with GCM mode (authenticated encryption)",
      "supports_text": true,
      "supports_file": false,
      "requires_keypair": false
    },
    "aes_cbc": {
      "name": "AES-CBC", 
      "description": "AES-256 with CBC mode and HMAC authentication",
      "supports_text": true,
      "supports_file": true,
      "requires_keypair": false
    },
    "xchacha": {
      "name": "XChaCha20-Poly1305",
      "description": "XChaCha20 stream cipher with Poly1305 authentication",
      "supports_text": true,
      "supports_file": true,
      "requires_keypair": false
    },
    "rsa_hybrid": {
      "name": "RSA Hybrid",
      "description": "RSA-4096 with AES hybrid encryption",
      "supports_text": true,
      "supports_file": true,
      "requires_keypair": true
    }
  }
}
```

### 2. Generate RSA Key Pair

Generate RSA key pairs for hybrid encryption algorithms.

**Endpoint**: `POST /api/generate-keypair`

**Request Body**:
```json
{
  "algorithm": "rsa_hybrid"
}
```

**Response**:
```json
{
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### 3. Text Encryption

Encrypt text using various algorithms.

**Endpoint**: `POST /api/encrypt`

**Content-Type**: `application/json`

#### Password-based Algorithms (AES-GCM, AES-CBC, XChaCha20)

**Request Body**:
```json
{
  "message": "Hello, World!",
  "password": "your_secure_password",
  "algorithm": "aes_gcm"
}
```

#### Key-based Algorithms (RSA Hybrid)

**Request Body**:
```json
{
  "message": "Hello, World!",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "algorithm": "rsa_hybrid"
}
```

**Response**:
```json
{
  "result": "base64_encrypted_text",
  "algorithm": "aes_gcm"
}
```

### 4. Text Decryption

Decrypt text using various algorithms.

**Endpoint**: `POST /api/decrypt`

**Content-Type**: `application/json`

#### Password-based Algorithms

**Request Body**:
```json
{
  "message": "base64_encrypted_text",
  "password": "your_secure_password", 
  "algorithm": "aes_gcm"
}
```

#### Key-based Algorithms

**Request Body**:
```json
{
  "message": "base64_encrypted_text",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "algorithm": "rsa_hybrid"
}
```

**Response**:
```json
{
  "result": "Hello, World!"
}
```

### 5. File Encryption

Encrypt files and download the encrypted result.

**Endpoint**: `POST /api/encrypt`

**Content-Type**: `multipart/form-data`

**Form Data**:
- `file`: File to encrypt
- `enc_password`: Encryption password
- `algorithm`: Algorithm to use (`aes_cbc`, `xchacha`, `rsa_hybrid`)

**Response**: Binary file download with `.{algorithm}.encrypted` extension

### 6. File Decryption

Decrypt files and download the decrypted result.

**Endpoint**: `POST /api/decrypt`

**Content-Type**: `multipart/form-data`

**Form Data**:
- `file`: Encrypted file
- `enc_password`: Decryption password
- `algorithm`: Algorithm used (optional, auto-detected from filename)

**Response**: Binary file download with original filename

---

## 📤 PacShare File Sharing

### 1. Upload File for Sharing

Upload and encrypt a file for secure sharing with pickup URLs.

**Endpoint**: `POST /api/pacshare`

**Content-Type**: `multipart/form-data`

**Form Data**:
- `file`: File to upload and share
- `enc_password`: Password to encrypt the file
- `pickup_password`: Password required to access pickup page
- `algorithm`: Encryption algorithm (`aes_cbc`, `xchacha`, `rsa_hybrid`)
- `enable_2fa`: Set to `"on"` to enable 2FA (optional)

**Response**:
```json
{
  "pickup_url": "https://paccrypt.unnaturalll.dev/pickup/abc123def456",
  "qr_code_url": "https://paccrypt.unnaturalll.dev/qr/abc123def456",
  "totp_secret": "BASE32SECRET",
  "service_name": "PacCrypt File: document.pdf..."
}
```

**Note**: QR code URL and TOTP fields only present if 2FA is enabled.

### 2. Generate 2FA QR Code

Get QR code for 2FA setup for a specific file.

**Endpoint**: `GET /qr/{file_id}`

**Response**: PNG image (QR code)

---

## 🛠️ Administrative Endpoints

### 1. Admin Setup

Create initial admin account (first-time setup only).

**Endpoint**: `POST /admin-setup`

**Content-Type**: `application/x-www-form-urlencoded`

**Form Data**:
- `username`: Admin username
- `password`: Admin password
- `enable_2fa`: Set to `"on"` to enable 2FA (optional)

### 2. Admin Login

Authenticate admin user and create session.

**Endpoint**: `POST /admin-login`

**Content-Type**: `application/x-www-form-urlencoded`

**Form Data**:
- `username`: Admin username
- `password`: Admin password
- `totp_code`: 2FA code (if 2FA enabled)

### 3. Admin Logout

End admin session.

**Endpoint**: `GET /admin-logout`

### 4. View Admin Logs

Get encrypted admin activity logs.

**Endpoint**: `GET /admin-logs`

**Response**:
```json
{
  "logs": [
    "[2025-01-15 10:30:00] Admin login successful.",
    "[2025-01-15 10:31:00] File abc123 downloaded and deleted."
  ]
}
```

### 5. Server Control

#### Restart Server
**Endpoint**: `POST /restart-server`

#### Switch to Development Mode
**Endpoint**: `POST /admin-switch-dev-mode`

#### Switch to Production Mode  
**Endpoint**: `POST /admin-switch-prod-mode`

#### Update from GitHub
**Endpoint**: `POST /admin-update-server`

### 6. File Management

#### Clear All Uploads
**Endpoint**: `POST /admin-clear-uploads`

### 7. Admin Account Management

#### Change Password
**Endpoint**: `POST /admin-change-password`

**Form Data**:
- `current_password`: Current admin password
- `new_password`: New admin password

#### Enable 2FA
**Endpoint**: `POST /admin-enable-2fa`

#### Disable 2FA
**Endpoint**: `POST /admin-disable-2fa`

**Form Data**:
- `totp_code`: Current 2FA code

#### Reset Admin Credentials
**Endpoint**: `POST /admin-reset`

---

## ❌ Error Handling

All API endpoints return appropriate HTTP status codes and error messages.

### Common HTTP Status Codes

- `200 OK`: Successful operation
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

### Error Response Format

```json
{
  "error": "Descriptive error message"
}
```

### Common Errors

- `"Missing message"`: Required message field not provided
- `"Invalid algorithm"`: Unsupported encryption algorithm
- `"Algorithm does not support text/file operations"`: Algorithm limitation
- `"Public/Private key required for this algorithm"`: Missing key for RSA
- `"Password required"`: Missing password for symmetric algorithms
- `"Encryption/Decryption failed"`: Cryptographic operation failed

---

## 🌟 Examples

### Self-Hosted Usage

Replace `localhost:5000` with your server's IP address or domain.

#### Text Encryption Example

```bash
curl -X POST "http://localhost:5000/api/encrypt" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Confidential information",
    "password": "super_secure_password",
    "algorithm": "aes_gcm"
  }'
```

#### File Upload Example

```bash
curl -X POST "http://localhost:5000/api/pacshare" \
  -F "file=@confidential.pdf" \
  -F "enc_password=file_encryption_key" \
  -F "pickup_password=pickup_key_123" \
  -F "algorithm=aes_cbc" \
  -F "enable_2fa=on"
```

#### RSA Key Generation and Usage

```bash
# 1. Generate key pair
curl -X POST "http://localhost:5000/api/generate-keypair" \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "rsa_hybrid"}' > keys.json

# 2. Extract public key and encrypt
PUBLIC_KEY=$(cat keys.json | jq -r '.public_key')
curl -X POST "http://localhost:5000/api/encrypt" \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"RSA encrypted message\",
    \"public_key\": \"$PUBLIC_KEY\",
    \"algorithm\": \"rsa_hybrid\"
  }"
```

### Official Instance Usage

#### Text Encryption with Official API

```bash
curl -X POST "https://paccrypt.unnaturalll.dev/api/encrypt" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello from the official API!",
    "password": "my_password_123",
    "algorithm": "xchacha"
  }'
```

#### PacShare Upload to Official Instance

```bash
curl -X POST "https://paccrypt.unnaturalll.dev/api/pacshare" \
  -F "file=@document.docx" \
  -F "enc_password=encrypt_me_please" \
  -F "pickup_password=come_get_it" \
  -F "algorithm=xchacha"
```

#### File Encryption with Official API

```bash
curl -X POST "https://paccrypt.unnaturalll.dev/api/encrypt" \
  -F "file=@sensitive_data.txt" \
  -F "enc_password=strong_password" \
  -F "algorithm=aes_cbc" \
  -o encrypted_file.aes_cbc.encrypted
```

### Python Integration Example

```python
import requests
import json

# Official API base URL
BASE_URL = "https://paccrypt.unnaturalll.dev"

# Text encryption
def encrypt_text(message, password, algorithm="aes_gcm"):
    response = requests.post(f"{BASE_URL}/api/encrypt", 
        json={
            "message": message,
            "password": password,
            "algorithm": algorithm
        })
    return response.json()

# File sharing via PacShare
def share_file(file_path, enc_password, pickup_password, algorithm="aes_cbc"):
    with open(file_path, 'rb') as f:
        response = requests.post(f"{BASE_URL}/api/pacshare",
            files={"file": f},
            data={
                "enc_password": enc_password,
                "pickup_password": pickup_password,
                "algorithm": algorithm
            })
    return response.json()

# Usage examples
encrypted = encrypt_text("Secret message", "my_password")
print(f"Encrypted: {encrypted['result']}")

file_share = share_file("document.pdf", "encrypt123", "pickup123")
print(f"Pickup URL: {file_share['pickup_url']}")
```

### JavaScript/Browser Example

```javascript
// Text encryption using fetch API
async function encryptText(message, password, algorithm = 'aes_gcm') {
    const response = await fetch('https://paccrypt.unnaturalll.dev/api/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            message: message,
            password: password,
            algorithm: algorithm
        })
    });
    
    return await response.json();
}

// File upload for sharing
async function shareFile(fileInput, encPassword, pickupPassword) {
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('enc_password', encPassword);
    formData.append('pickup_password', pickupPassword);
    formData.append('algorithm', 'aes_cbc');
    
    const response = await fetch('https://paccrypt.unnaturalll.dev/api/pacshare', {
        method: 'POST',
        body: formData
    });
    
    return await response.json();
}

// Usage
encryptText("Hello API!", "password123").then(result => {
    console.log("Encrypted:", result.result);
});
```

---

## 🔒 Security Best Practices

### For API Consumers

1. **Always use HTTPS** in production environments
2. **Use strong passwords** with high entropy
3. **Implement proper error handling** for failed operations
4. **Don't log sensitive data** like passwords or private keys
5. **Validate inputs** before sending to the API
6. **Use 2FA** for sensitive file shares
7. **Implement rate limiting** to prevent abuse

### For Self-Hosted Instances

1. **Configure reverse proxy** (nginx/apache) with HTTPS
2. **Set up firewall rules** to restrict access
3. **Regular security updates** for all dependencies
4. **Monitor admin logs** for suspicious activity
5. **Backup encrypted data** regularly
6. **Use strong admin passwords** with 2FA enabled
7. **Configure CORS** appropriately for your use case

---

## 🚀 Advanced Usage

### Batch Operations

You can process multiple files or messages by making multiple API calls. Consider implementing:

- **Concurrent requests** for better performance
- **Progress tracking** for large batches
- **Error retry logic** for failed operations

### Integration Patterns

- **CLI Tools**: Build command-line interfaces using the API
- **Web Applications**: Integrate encryption into existing apps
- **Mobile Apps**: Use the API for mobile encryption needs
- **Automation Scripts**: Automate encryption workflows

### Performance Considerations

- **File Size Limits**: Check instance-specific upload limits
- **Rate Limiting**: Respect API rate limits if implemented
- **Caching**: Cache algorithm information to reduce API calls
- **Connection Pooling**: Reuse HTTP connections for multiple requests

---

*For more information, see the main [README.md](README.md) or visit the [official instance](https://paccrypt.unnaturalll.dev).*