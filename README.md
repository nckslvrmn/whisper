# <img src="docs/s3.svg" alt="S³" width="50" height="50">: Secure Secret Share

A secure, light-weight, and ephemeral secret sharing service. **S³** uses scrypt and AES-256-GCM to ensure the confidentiality, integrity, and authenticity of data sent through the service.

## Dependencies

**S³** requires golang 1.23 or greater and utilizes either AWS DynamoDB and S3 or Google Cloud Firestore and Cloud Storage for the storage of encrypted secrets.

## Build

```console
$ docker build -t s3-secure-share .
...
=> exporting layers
```

## Configuration

To ensure the best security practices, the methods used for KDF and
encryption/decryption have been baked into the code itself. There are a few
options that can be configured. All of these should be passed in to the function
via environment variables.

| VARIABLE             | REQUIRED           | DESCRIPTION                                                          |
| ------------------- | :----------------: | -------------------------------------------------------------------- |
| DYNAMO_TABLE        | :white_check_mark:*| Name of the dynamodb table in which to store secrets                 |
| S3_BUCKET           | :white_check_mark:*| Name of the S3 bucket in which to store encrypted files              |
| GCP_PROJECT_ID      | :white_check_mark:*| Google Cloud project ID for Firestore                                |
| FIRESTORE_DATABASE  | :white_check_mark:*| Name of the Firestore database in which to store secrets             |
| GCS_BUCKET          | :white_check_mark:*| Name of the Google Cloud Storage bucket for encrypted files          |
| AWS_REGION          | :x:                | (default: us-east-1) AWS region of the s3 bucket and dynamo db table |

*Note: You must configure either AWS (DYNAMO_TABLE + S3_BUCKET) or Google Cloud (GCP_PROJECT_ID + FIRESTORE_DATABASE + GCS_BUCKET) environment variables depending on which storage backend you want to use.

## Cloud Authentication

For Google Cloud services, you need to set up authentication:
1. Set the GOOGLE_APPLICATION_CREDENTIALS environment variable to point to your service account key file, or
2. Use Application Default Credentials if running in Google Cloud

The service account or credentials used must have the following permissions:
- Firestore: `datastore.user` role or equivalent custom role with read/write permissions
- Cloud Storage: `storage.objectViewer` and `storage.objectCreator` roles or equivalent permissions

For AWS services, you need to set up authentication using one of these methods:
1. Set the AWS_PROFILE environment variable to use a specific profile from your AWS credentials file
2. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables directly
3. Use IAM instance profiles if running on AWS EC2
4. Use AWS Default Credential Provider Chain which will automatically try the above methods in order

The AWS credentials used must have the following permissions:
- DynamoDB: `dynamodb:PutItem`, `dynamodb:GetItem`, `dynamodb:DeleteItem`, `dynamodb:UpdateItem` on the table
- S3: `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on the bucket

## API Usage

Because **S³** uses static pages for the UI, the APIs can be accessed directly. To interact with the APIs, here are some examples via CURL. To send and receive a string based secret:

```console
$ curl -X POST -H "Content-Type: application/json" https://URL/encrypt -d '{"secret": "super secret text", "view_count": 1}'
{"secret_id": "HrVfOn1aoqKHeRKi", "passphrase": "iT95_B9p9PSMcP-hH9OGS81w9FZVTEpf"}

$ curl -X POST -H "Content-Type: application/json" https://URL/decrypt -d '{"secret_id": "HrVfOn1aoqKHeRKi", "passphrase": "iT95_B9p9PSMcP-hH9OGS81w9FZVTEpf"}'
{"data": "super secret text"}
```

The string based secret sharing works by passing the `/encrypt` route secret text and a view count via a JSON payload. To retrieve the secret, send the `/decrypt` route the generated secret id and passphrase.

The file based API works similarly:

```console
$ cat test.txt
hello

$ curl -X POST -F "file=@test.txt;type=text/plain" https://URL/encrypt_file
{"secret_id": "97tfNQQBAl0w2zNE", "passphrase": "CPIX4PeLALaLaNLVFM~oNjM!N&bjZ377"}

$ curl -OJ -H "Content-Type: application/json" -X POST https://URL/decrypt -d '{"secret_id": "97tfNQQBAl0w2zNE", "passphrase": "CPIX4PeLALaLaNLVFM~oNjM!N&bjZ377"}'

$ cat test.txt
hello
```

This time, the data payload is the file to encrypt. This is done using the multipart form mechanism so that it behaves the same in browser and against the API. To retrieve this file, hit the same `/decrypt` route with the same payload as the string secret. This will return the file and the proper `Content-Disposition` header needed to understand it is an attachment that should be downloaded, and will include the file name.

## Security Features

**S³** utilizes the best in business algorithms and functions for proper encryption at rest that guarantees information security. There is another domain of security however not covered by the service itself. That is encryption in transit. As previously mentioned, an nginx configuration file is provided that can serve as the web server proxy. It is highly recommended to follow or use this configuration as it contains all the options required for modern best practices on encryption in transit. When configuring these best practice options, there is a somewhat significant reduction in compatibility for older devices but considering the security gains this is a worthwhile sacrifice.

**S³** uses three main security standards to ensure full information
security.

### AES

The first of which is the encryption/decryption mode. **S³** uses [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode). This uses the AES standard with a key size of 256 bits and the GCM mode. GCM is a combination of Galois field authentication and a counter mode algorithm and can be further documented . GCM was designed to be performant (via parallelized operations) and to guarantee authenticity and confidentiality. By using an AEAD (authenticated encryption with associated data) cipher mode, one can guarantee that the ciphertext maintains integrity upon decryption and will fail to decrypt if someone attempts to modify the ciphertext while it remains encrypted.

### Scrypt

[Scrypt](https://en.wikipedia.org/wiki/Scrypt) is a password-based key derivation function and us used to generate the AES key used for encryption and decryption. Scrypt was designed to take input
parameters that relate largely to the hardware resources available. Because it uses the most resources available to it, brute force or custom hardware attacks become infeasible.

### Randomness

Go's `crypto/rand` package comes with functions that allow for access to random number generation from the `/dev/urandom` entropy pool device.
