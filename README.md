# 🔐 Whisper

> End-to-end encrypted secret sharing service with WebAssembly-powered client-side encryption. Share sensitive information with true zero-knowledge architecture - your secrets are encrypted in your browser before ever leaving your device.

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.23-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/github/license/nckslvrmn/secure_secret_share)](LICENSE)
[![Security](https://img.shields.io/badge/encryption-AES--256--GCM-green?logo=shield)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![KDF](https://img.shields.io/badge/KDF-scrypt-blue)](https://en.wikipedia.org/wiki/Scrypt)
[![WASM](https://img.shields.io/badge/WASM-Enabled-orange?logo=webassembly)](https://webassembly.org/)

## ✨ Features

- **🔐 True End-to-End Encryption** - All encryption/decryption happens in your browser via WebAssembly
- **🔒 Military-Grade Encryption** - AES-256-GCM ensures confidentiality, integrity, and authenticity
- **⏱️ Self-Destructing Secrets** - Set view limits and watch secrets vanish after access
- **📄 Text & File Support** - Share passwords, API keys, documents, or any sensitive files
- **🚀 Lightning Fast** - Go backend with WASM-powered frontend for maximum performance
- **☁️ Multi-Storage Support** - AWS (DynamoDB/S3), Google Cloud (Firestore/GCS), or local SQLite/filesystem
- **🔑 True Zero-Knowledge** - Server only stores encrypted data and never has access to plaintext or keys
- **🎨 Clean Web UI** - Beautiful interface with client-side encryption
- **🛡️ Scrypt KDF** - Hardware-resistant key derivation prevents brute force attacks
- **🌐 No Server Trust Required** - Encryption keys never leave your browser

## 🚀 Quick Start

### 🐳 Docker Setup

```bash
# Pull and run with AWS backend
docker run -d \
  --name secure_secret_share \
  -p 8080:8080 \
  -e DYNAMO_TABLE=secrets \
  -e S3_BUCKET=encrypted-files \
  -e AWS_REGION=us-east-1 \
  secure_secret_share:latest

# Or with Google Cloud backend
docker run -d \
  --name secure_secret_share \
  -p 8080:8080 \
  -e GCP_PROJECT_ID=your-project \
  -e FIRESTORE_DATABASE=secrets-db \
  -e GCS_BUCKET=encrypted-files \
  secure_secret_share:latest

# Or with local storage (SQLite + filesystem)
docker run -d \
  --name secure_secret_share \
  -p 8080:8080 \
  -v /path/to/local/storage:/data \
  secure_secret_share:latest
```

### 🐳 Docker Compose

Ready-to-use Docker Compose configurations are available in the `docs/` directory:

- **AWS Backend**: [`docs/docker-compose.aws.yml`](docs/docker-compose.aws.yml) - DynamoDB + S3
- **Google Cloud Backend**: [`docs/docker-compose.gcp.yml`](docs/docker-compose.gcp.yml) - Firestore + Cloud Storage
- **Local Storage**: [`docs/docker-compose.local.yml`](docs/docker-compose.local.yml) - SQLite + filesystem with persistent volume

> **Note**: All compose files require updating the image TAG and storage-specific configuration values before use. See the comments in each file for guidance.

```bash
# Start with AWS backend (update environment variables first)
docker-compose -f docs/docker-compose.aws.yml up -d

# Start with Google Cloud backend (update project ID and add credentials)
docker-compose -f docs/docker-compose.gcp.yml up -d

# Start with local storage (no configuration needed)
docker-compose -f docs/docker-compose.local.yml up -d
```

### 🏗️ Build from Source

```bash
# Clone the repository
git clone https://github.com/nckslvrmn/secure_secret_share.git
cd secure_secret_share

# Build the WASM module
make wasm

# Build the Docker image
docker build -t secure_secret_share .

# Or build locally
go build -o secure_secret_share main.go
```

## 🔧 Configuration

### Environment Variables

Choose your storage provider by configuring the appropriate variables:

#### ☁️ AWS Configuration
| Variable | Required | Description |
|----------|:--------:|-------------|
| `DYNAMO_TABLE` | ✅ | DynamoDB table name for storing encrypted secrets |
| `S3_BUCKET` | ✅ | S3 bucket name for storing encrypted files |
| `AWS_REGION` | ⚪ | AWS region (default: `us-east-1`) |

#### ☁️ Google Cloud Configuration
| Variable | Required | Description |
|----------|:--------:|-------------|
| `GCP_PROJECT_ID` | ✅ | Google Cloud project ID |
| `FIRESTORE_DATABASE` | ✅ | Firestore database name |
| `GCS_BUCKET` | ✅ | Cloud Storage bucket name |

#### 💾 Local Storage Configuration (Default Fallback)
When no AWS or GCP environment variables are configured, the application automatically falls back to local storage using SQLite and the filesystem.

| Volume Mount | Description |
|--------------|-------------|
| `/data` | Mount a local directory here to persist SQLite database and encrypted files |

> **Note**: Local storage does not automatically clean up expired secrets based on TTL. Manual cleanup may be required.

> **Storage Priority**: AWS → Google Cloud → Local (fallback)

## 🔑 Authentication

### AWS Authentication

Choose one of these methods:
1. **IAM Role** (Recommended for EC2/ECS)
2. **Environment Variables**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
3. **AWS Profile**: Set `AWS_PROFILE`
4. **Default Credential Chain**: Automatically tries all methods

Required IAM permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:DeleteItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/YOUR_TABLE_NAME"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME/*"
    }
  ]
}
```

### Google Cloud Authentication

1. **Service Account** (Recommended): Set `GOOGLE_APPLICATION_CREDENTIALS` to your key file path
2. **Application Default Credentials**: Automatic in GCP environments

Required roles:
- **Firestore**: `roles/datastore.user`
- **Cloud Storage**: `roles/storage.objectAdmin`

## 🌐 How It Works

### End-to-End Encryption Flow

1. **Client-side Encryption**: When you submit a secret through the web interface:
   - The WASM module generates a cryptographically secure passphrase
   - Your data is encrypted using AES-256-GCM entirely in your browser
   - Only the encrypted data is sent to the server

2. **Server Storage**: The backend:
   - Receives only encrypted data, never plaintext
   - Stores the encrypted blob with a unique ID
   - Has no ability to decrypt your data

3. **Decryption**: When retrieving a secret:
   - The encrypted data is fetched from the server
   - Decryption happens entirely in your browser using the passphrase
   - The server never sees the passphrase or decrypted content

### WebAssembly Module

The WASM module (`crypto.wasm`) provides:
- `encryptText`: Encrypts text secrets with configurable view counts and TTL
- `encryptFile`: Encrypts files with metadata
- `decryptText`: Decrypts text secrets
- `decryptFile`: Decrypts files and metadata
- `hashPassword`: Creates secure password hashes

All cryptographic operations use:
- **AES-256-GCM** for authenticated encryption
- **Scrypt** for key derivation (N=2^15, r=8, p=1)
- **Cryptographically secure random** for all nonces, salts, and passphrases

## 🛡️ Security Architecture

### 🔐 End-to-End Encryption Details

**S³** implements true end-to-end encryption with WebAssembly:

#### Client-Side Encryption (WASM)
- **Location**: All encryption happens in your browser via WebAssembly
- **Keys**: Generated client-side, never transmitted to server
- **Passphrase**: 32-character random string generated in browser
- **Zero-Trust**: Server cannot decrypt data even if compromised

#### AES-256-GCM
- **Algorithm**: Advanced Encryption Standard with 256-bit keys
- **Mode**: Galois/Counter Mode for authenticated encryption
- **Benefits**: Provides confidentiality, integrity, and authenticity in a single operation
- **Performance**: Parallelizable for high-speed encryption/decryption

#### Scrypt Key Derivation
- **Purpose**: Converts passphrases into encryption keys
- **Design**: Memory-hard function resistant to ASIC/GPU attacks
- **Parameters**: N=2^15, r=8, p=1 (32MB memory requirement)
- **Protection**: Makes brute-force attacks economically infeasible

#### Cryptographic Randomness
- **Source**: Browser's Web Crypto API for client-side operations
- **Server**: `/dev/urandom` via Go's `crypto/rand` for IDs only
- **Usage**: Secret IDs, passphrases, salts, and nonces
- **Entropy**: Cryptographically secure for all security operations

### 🔒 Security Best Practices

1. **Transport Security**: Always use HTTPS in production
2. **Secret Limits**: Set appropriate view counts for your use case
3. **Passphrase Storage**: Never log or persist passphrases
4. **Infrastructure**: Use private subnets for backend services
5. **Monitoring**: Enable CloudTrail/Cloud Audit Logs for access tracking

## 🌐 Production Deployment

### Recommended Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Clients   │────▶│  Load       │────▶│     S³      │
└─────────────┘     │  Balancer   │     │  Instances  │
                    └─────────────┘     └─────────────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │   Storage   │
                                        │ (AWS/GCP)   │
                                        └─────────────┘
```

### Nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name secrets.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Go](https://golang.org/) and [Echo Framework](https://echo.labstack.com/)
- Client-side encryption via [WebAssembly](https://webassembly.org/)
- Encryption powered by Go's [crypto](https://pkg.go.dev/crypto) package compiled to WASM
- Cloud storage via [AWS SDK](https://aws.github.io/aws-sdk-go-v2/) and [Google Cloud SDK](https://cloud.google.com/go)
- UI components from [Bootstrap](https://getbootstrap.com/)

---

<p align="center">
  Made with ❤️ for keeping secrets secret<br>
  <sub>Remember: Once viewed, secrets are gone forever! 🔥</sub>
</p>
