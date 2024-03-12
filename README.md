# Dfns Golang SDK

Welcome, builders 👋🔑 This repo holds Dfns Typescript SDK. Useful links:

- [Dfns Website](https://www.dfns.co)
- [Dfns API Docs](https://docs.dfns.co)

## BETA Warning

:warning: **Attention: This project is currently in BETA.**

This means that while we've worked hard to ensure its functionality, stability, and security, there may still be bugs, performance issues, or unexpected behavior. 


## Installation

```
go get github.com/dfns/dfns-sdk-go
```


## Concepts

### `CredentialSigner`

All state-changing requests made to the Dfns API need to be cryptographically signed by credentials registered with the User/Service Account.

> **Note:** To be more precise, it's not the request itself that needs to be signed, but rather a "User Action Challenge" issued by Dfns. For simplicity, we refer to this process as "request signing".

This request signature serves as cryptographic proof that only authorized entities are making the request. Without it, the request would result in an Unauthorized error.

Credentials currently support only Key Credentials (_refer to our [API documentation](https://docs.dfns.co/dfns-docs/getting-started/authentication-authorization#credentials) for more details_). Key Credentials are responsible for signing the challenge.

#### `AsymmetricKeySigner`

This functionality is exposed in the `pkg/api` package and implements the `CredentialSigner` interface. It is primarily intended for server-side use. Although it could be employed client-side, we don't recommend it. In a browser context, any key-based crypto signing should be handled within a service worker. We are actively working on additional helper classes to facilitate this support.

```golang
import (
  .....
	"github/dfns/dfns-sdk-go/pkg/credentials"
)

conf := &credentials.AsymmetricKeySignerConfig{
		PrivateKey: os.Getenv("DFNS_PRIVATE_KEY"), // Credential private key
		CredId:     os.Getenv("DFNS_CRED_ID"),     // Credential Id
		AppOrigin:  os.Getenv("DFNS_APP_ORIGIN"),  // Application's origin, should match the Application registered with Dfns
	}
```

- `credential Id`: ID of the Credential registered with the auth token you’re using (Personal Access Token, or Service Account Token). In Dfns dashboard, you can find it next to your token (in `Settings` > `My Access Tokens` or `Settings > Service Accounts`)
- `Private Key`: private key (in .pem format) which only you have, associated with the public key you registered when you created your PAT / Service Account.
- `App Origin`: Origin of the client-side Application registered with Dfns. In Dfns dashboard, you can find Applications in `Settings > Application`

### `DfnsApiClient`

`DfnsApiClient` is the main Dfns client, holding most supported functionalities of Dfns API.

It needs to be authenticated, so `DfnsApiClient` needs to be passed a valid `authToken`. This `authToken` can be:

- a Service Account token - _long-lived_
- a User Personal Access Token (PAT) - _long-lived_
- a User token issued after on User login - _expires_

`DfnsApiClient` also needs to be passed a [CredentialSigner](#credentialsigner), in order to sign requests.

The `DfnsApiClient` provides a single function that creates a http client -> `CreateDfnsApiClient`
The http.Client returned will handle all the authentification process.

When the user performs a `POST, PUT or DELETE` using the client, it will automatically perform a `useraction` process (aka challenge signing).
If for a `POST, PUT or DELETE` endpoint, the `useraction` is not required, you should provide the header:

`x-dfns-useraction` to `false`. Doing that, it indicates the client to skip the challenge signing.

Please refer to the [Dfns API Docs](https://docs.dfns.co) to know which endpoints need a user action.

_Note: You can include a context directly in your httprequest if you want some control on shutdown logic_

```golang
import (
  .....
	api "github/dfns/dfns-sdk-go/pkg/dfns_api_client"
	"github/dfns/dfns-sdk-go/pkg/credentials"
)

signer := ... // a Credential Signer (webauthN or key signer from section above)

// Create a DfnsApiClient instance
apiOptions, err := api.NewDfnsBaseApiOptions(&api.DfnsBaseApiConfig{
	AppId:     os.Getenv("DFNS_APP_ID"),     // ID of the Application registered with DFNS
	AuthToken: os.Getenv("DFNS_AUTH_TOKEN"), // an auth token
	BaseUrl:   os.Getenv("DFNS_API_URL"),    // base Url of DFNS API
}, signer)
if err != nil {
	fmt.Printf("Error creating DfnsApiOptions: %s", err)
	return
}

dfnsClient := api.CreateDfnsApiClient(apiOptions)

// Create wallet
walletData := struct {
		Network string `json:"network"`
	}{
		Network: "EthereumGoerli",
	}

jsonData, err := json.Marshal(walletData)
if err != nil {
  return fmt.Errorf("error marshaling JSON: %v", err)
}

req, err := http.NewRequest("POST", apiOptions.BaseUrl+"/wallets", bytes.NewBuffer(jsonData))
if err != nil {
  return fmt.Errorf("error creating POST request: %v", err)
}

response, err := dfnsClient.Do(req)
if err != nil {
  return fmt.Errorf("error creating wallet: %v", err)
}
```