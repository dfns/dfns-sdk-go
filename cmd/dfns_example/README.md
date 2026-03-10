# Dfns Golang SDK Example

This example shows how to use the Dfns Go SDK to create a wallet and retrieve its balance.

To run the example, you need to provide a config.yaml (see `config.yaml.example`) or/and the right environment variables
  (here for simplicity we use a `.env` file but it's not mandatory).
Copy the `config.yaml.example` and set the following values:

``` yaml
api:
  authToken: "the `authToken` from above, the value should start with `eyJ0...`"
  baseUrl: "https://api.dfns.wtf"

keySigner:
  privateKey: >
    the private key from the step 'generate a keypair', the newlines should not be a problem
  credId: "the `Signing Key Cred ID` from above"

All these values can be overridden by environment variables with the following pattern:
DFNS_API_FIELD or DFNS_KEYSIGNER_FIELD (All should be uppercase) (see .env.example)
You can choose to use only environment variables.

then

> cd cmd/dfns_example
> go run *.go

2024/03/06 09:49:11 Creating a new wallet
2024/03/06 09:49:13 Wallet ID: wa-5l3vn-6g2j2-97pqr0crua0mk5am
2024/03/06 09:49:13 Retrieving native balance for wallet: wa-5l3vn-6g2j2-97pqr0crua0mk5am
2024/03/06 09:49:13 Native Balance: 0