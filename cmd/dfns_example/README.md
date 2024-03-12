# Dfns Golang SDK Example

This example gives an example on how to use the dfns api `http.Client` along with a creadentials signer (here `AsymmetricKeySigner`).

This example performs two different requests, one with a challenge signing to create a wallet,
and one without to retrieve wallet balance.

To run the example, you need to provide a config.yaml (see `config.yaml.example`) or/and the right environment variables (here for simplicity we use a `.env` file but it's not mandatory).
Copy the `config.yaml.example`  and set the following values:

``` yaml
api:
  appId: "the `App ID` from above"
  authToken: "the `authToken` from above, the value should start with `eyJ0...`"
  baseUrl: "https://api.dfns.wtf"

keySigner:
  privateKey: >
   the private key from the step 'generate a keypair', the newlines should not be a problem
  appOrigin: "http://localhost:3000"
  credId: "the `Signing Key Cred ID` from above"
  algorithm: "The algorithm used by keysigner to prehash message for ecdsa and rsa"

```

All these values can be overriden by encironment variable with the following pattern:
`DFNS_API_FIELD` or `DFNS_KEYSIGNER_FIELD` (All should be uppercase) (see .env.example)
You can choose to use only environment variables.

then


```shell
> cd cmd/dfns_example
> go run *.go

2024/03/06 09:49:11 Creating a new wallet
2024/03/06 09:49:13 Wallet ID: wa-5l3vn-6g2j2-97pqr0crua0mk5am
2024/03/06 09:49:13 Retrieving native balance for wallet: wa-5l3vn-6g2j2-97pqr0crua0mk5am
2024/03/06 09:49:13 Native Balance: 0
```