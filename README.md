Author [![GitHub](https://img.shields.io/badge/GitHub-sujoydev99-blue?style=flat&logo=github)](https://github.com/sujoydev99)

# Node Secret Manager

A secure secret management server with encryption, key splitting, and versioning support.

## Prerequisites

- Node.js >=22.0.0
- SQLite3

## Installation

```sh
yarn install
```

## Configuration

Create a `.env` file:

```sh
SECRETS_DB_PATH=/path/to/secrets/directory
```

If `SECRETS_DB_PATH` is not specified, it defaults to tmp.

## Usage Flow

1. **Start the server**:

   ```sh
   node index.js
   ```

   Server runs on port 3000.

2. **Initialize the vault**:

   ```sh
   curl -X POST http://localhost:3000/init
   ```

3. **Split the master key** (generates key shares):

   ```sh
   curl -X POST http://localhost:3000/split-key \
     -H "Content-Type: application/json" \
     -d '{"shares": 5, "threshold": 3}'
   ```

   Save the returned key shares securely.

4. **Unseal the vault** (requires at least 3 shares):

   ```sh
   curl -X POST http://localhost:3000/unseal \
     -H "Content-Type: application/json" \
     -d '{"shares": ["share1", "share2", "share3"]}'
   ```

5. **Store a secret**:

   ```sh
   curl -X POST http://localhost:3000/store-secret \
     -H "Content-Type: application/json" \
     -d '{"key": "myapp/db/password", "value": "secret123"}'
   ```

6. **Retrieve a secret**:
   ```sh
   curl http://localhost:3000/get-secret/myapp/db/password
   ```

## Security Features

- AES-256-GCM encryption
- Shamir's Secret Sharing for key splitting
- Key rotation support
- Secret versioning
- Seal/Unseal mechanism

The vault starts in a sealed state and requires key shares to unseal before any operations can be performed.

## API Endpoints

- `POST /init` - Initialize vault
- `POST /split-key` - Generate key shares
- `POST /unseal` - Unseal vault
- `POST /seal` - Seal vault
- `POST /store-secret` - Store a secret
- `GET /get-secret/:key` - Retrieve a secret
- `POST /rotate-key` - Rotate encryption key
