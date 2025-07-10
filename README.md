# 🔐 S³: Secure Secret Share

> A blazing-fast, ephemeral secret sharing service built with Go. Share sensitive information securely with military-grade encryption that self-destructs after viewing.

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.23-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/github/license/nckslvrmn/secure_secret_share)](LICENSE)
[![Security](https://img.shields.io/badge/encryption-AES--256--GCM-green?logo=shield)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![KDF](https://img.shields.io/badge/KDF-scrypt-blue)](https://en.wikipedia.org/wiki/Scrypt)

## ✨ Features

- **🔒 Military-Grade Encryption** - AES-256-GCM ensures confidentiality, integrity, and authenticity
- **⏱️ Self-Destructing Secrets** - Set view limits and watch secrets vanish after access
- **📄 Text & File Support** - Share passwords, API keys, documents, or any sensitive files
- **🚀 Lightning Fast** - Built with Go for maximum performance
- **☁️ Multi-Cloud Support** - Choose between AWS (DynamoDB/S3) or Google Cloud (Firestore/GCS)
- **🔑 Zero-Knowledge** - Server never sees unencrypted data
- **🎯 Simple API** - RESTful endpoints for easy integration
- **🎨 Clean Web UI** - Beautiful interface for non-technical users
- **🛡️ Scrypt KDF** - Hardware-resistant key derivation prevents brute force attacks

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
```

### 🏗️ Build from Source

```bash
# Clone the repository
git clone https://github.com/nckslvrmn/secure_secret_share.git
cd secure_secret_share

# Build the Docker image
docker build -t secure_secret_share .

# Or build locally
go build -o secure_secret_share main.go
```

## 🔧 Configuration

### Environment Variables

Choose your cloud provider by configuring the appropriate variables:

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

> **Note**: Configure either AWS or Google Cloud variables, not both!

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

## 📡 API Usage

### 🔐 Encrypt Text Secret

```bash
curl -X POST https://your-domain/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "my-super-secret-password",
    "view_count": 1
  }'

# Response:
{
  "secret_id": "HrVfOn1aoqKHeRKi",
  "passphrase": "iT95_B9p9PSMcP-hH9OGS81w9FZVTEpf"
}
```

### 🔓 Decrypt Text Secret

```bash
curl -X POST https://your-domain/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "secret_id": "HrVfOn1aoqKHeRKi",
    "passphrase": "iT95_B9p9PSMcP-hH9OGS81w9FZVTEpf"
  }'

# Response:
{
  "data": "my-super-secret-password"
}
```

### 📎 Encrypt File

```bash
curl -X POST https://your-domain/encrypt_file \
  -F "file=@/path/to/secret.pdf;type=application/pdf"

# Response:
{
  "secret_id": "97tfNQQBAl0w2zNE",
  "passphrase": "CPIX4PeLALaLaNLVFM~oNjM!N&bjZ377"
}
```

### 📥 Decrypt File

```bash
curl -OJ -X POST https://your-domain/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "secret_id": "97tfNQQBAl0w2zNE",
    "passphrase": "CPIX4PeLALaLaNLVFM~oNjM!N&bjZ377"
  }'

# File will be downloaded with original filename
```

## 🛡️ Security Architecture

### 🔐 Encryption Details

**S³** implements defense-in-depth security:

#### AES-256-GCM
- **Algorithm**: Advanced Encryption Standard with 256-bit keys
- **Mode**: Galois/Counter Mode for authenticated encryption
- **Benefits**: Provides confidentiality, integrity, and authenticity in a single operation
- **Performance**: Parallelizable for high-speed encryption/decryption

#### Scrypt Key Derivation
- **Purpose**: Converts passphrases into encryption keys
- **Design**: Memory-hard function resistant to ASIC/GPU attacks
- **Parameters**: Tuned for 100ms+ derivation time on modern hardware
- **Protection**: Makes brute-force attacks economically infeasible

#### Cryptographic Randomness
- **Source**: `/dev/urandom` via Go's `crypto/rand`
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
- Encryption powered by Go's [crypto](https://pkg.go.dev/crypto) package
- Cloud storage via [AWS SDK](https://aws.github.io/aws-sdk-go-v2/) and [Google Cloud SDK](https://cloud.google.com/go)
- UI components from [Bootstrap](https://getbootstrap.com/)

---

<p align="center">
  Made with ❤️ for keeping secrets secret<br>
  <sub>Remember: Once viewed, secrets are gone forever! 🔥</sub>
</p>
