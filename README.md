# Dfns Go SDK

[![Go Build](https://github.com/dfns/dfns-sdk-go/actions/workflows/build.yaml/badge.svg)](https://github.com/dfns/dfns-sdk-go/actions/workflows/build.yaml)
[![Coverage](https://codecov.io/github/dfns/dfns-sdk-go/graph/badge.svg?token=0VPR2C7OZJ)](https://codecov.io/github/dfns/dfns-sdk-go)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/dfns/dfns-sdk-go/blob/master/LICENSE)
[![Godoc](https://godoc.org/github.com/dfns/dfns-sdk-go/v2?status.svg)](https://godoc.org/github.com/dfns/dfns-sdk-go/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/dfns/dfns-sdk-go/v2)](https://goreportcard.com/report/github.com/dfns/dfns-sdk-go/v2)

Welcome, builders. This repo holds the Dfns Golang SDK. Useful links:

- [Dfns Website](https://www.dfns.co)
- [Dfns API Docs](https://docs.dfns.co)

## Installation

```bash
go get github.com/dfns/dfns-sdk-go/v2
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    dfns "github.com/dfns/dfns-sdk-go/v2"
)

func main() {
    // Create the client (read-only operations)
    dfnsClient, err := dfns.NewClient(dfns.Options{
        AuthToken: "your-auth-token",
        // BaseURL: "https://api.dfns.io", // Optional, this is the default
    })
    if err != nil {
        log.Fatal(err)
    }

    // List wallets
    ctx := context.Background()
    wallets, err := dfnsClient.Wallets.ListWallets(ctx, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Found %d wallets\n", len(wallets.Items))
}
```

## User Action Signing

Some operations (like creating wallets or signing transactions) require user action signing.
Configure a signer to enable these operations:

```go
package main

import (
    "context"
    "log"
    "os"

    dfns "github.com/dfns/dfns-sdk-go/v2"
    "github.com/dfns/dfns-sdk-go/v2/signer"
    "github.com/dfns/dfns-sdk-go/v2/wallets"
)

func main() {
    // Load your private key
    privateKeyPEM, err := os.ReadFile("private_key.pem")
    if err != nil {
        log.Fatal(err)
    }

    // Create a signer (supports Ed25519, ECDSA, RSA keys)
    keySigner, err := signer.NewKeySigner(
        "cr-xxx-xxx",              // Your credential ID
        string(privateKeyPEM),     // PEM-encoded private key
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create client with signer
    dfnsClient, err := dfns.NewClient(dfns.Options{
        AuthToken: "your-auth-token",
        Signer:    keySigner,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Operations requiring signatures will automatically sign
    ctx := context.Background()
    wallet, err := dfnsClient.Wallets.CreateWallet(ctx, wallets.CreateWalletRequest{
        Network: "EthereumSepolia",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created wallet: %s\n", wallet.ID)
}
```

## Available Domains

The client provides access to the following API domains:

- `client.Auth` - Authentication and user management (53 endpoints)
- `client.Exchanges` - Exchange integrations (9 endpoints)
- `client.FeeSponsors` - Fee sponsor management (7 endpoints)
- `client.Keys` - Key management (12 endpoints)
- `client.Networks` - Network information (7 endpoints)
- `client.Permissions` - Permission management (8 endpoints)
- `client.Policies` - Policy management (8 endpoints)
- `client.Signers` - Signer management (2 endpoints)
- `client.Staking` - Staking operations (6 endpoints)
- `client.Wallets` - Wallet operations (31 endpoints)
- `client.Webhooks` - Webhook subscriptions (8 endpoints)
- `client.Swaps` - Token swap operations (5 endpoints)
- `client.Agreements` - Agreement management (2 endpoints)
- `client.Allocations` - Allocation management (5 endpoints)

Each domain provides typed methods for all available API endpoints.

## Error Handling

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"

    dfns "github.com/dfns/dfns-sdk-go/v2"
)

func main() {
    dfnsClient, err := dfns.NewClient(dfns.Options{
        AuthToken: "your-auth-token",
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    _, err = dfnsClient.Wallets.GetWallet(ctx, "invalid-wallet-id")
    if err != nil {
        var apiErr *dfns.APIError
        if errors.As(err, &apiErr) {
            fmt.Printf("API Error (status %d): %s\n", apiErr.StatusCode, apiErr.Body)
        } else {
            fmt.Printf("Error: %v\n", err)
        }
    }
}
```

## Supported Key Types

The `KeySigner` supports the following private key types:

| Algorithm | Description |
|-----------|-------------|
| Ed25519 | Edwards-curve Digital Signature Algorithm |
| ECDSA | Elliptic Curve DSA (P-256, secp256k1) |
| RSA | RSA PKCS#1 v1.5 with SHA-256 |

Keys can be in PKCS#8, PKCS#1 (RSA), or SEC 1 (EC) PEM format.

## License

MIT License - See LICENSE file for details.
