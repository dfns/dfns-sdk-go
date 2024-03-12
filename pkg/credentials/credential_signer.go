package credentials

type CredentialKind string

const (
	KeyCredential CredentialKind = "Key"
	// We can add various afterward
)

type KeyAssertion struct {
	Kind                CredentialKind      `json:"kind"`
	CredentialAssertion CredentialAssertion `json:"credentialAssertion"`
}

type CredentialAssertion struct {
	CredId     string `json:"credId"`
	ClientData string `json:"clientData"`
	Signature  string `json:"signature"`
	Algorithm  string `json:"algorithm"`
}

type CredentialTransport string

const (
	USB      CredentialTransport = "usb"
	NFC      CredentialTransport = "nfc"
	BLE      CredentialTransport = "ble"
	Internal CredentialTransport = "internal"
)

type AllowCredential struct {
	Type       string                `json:"type"`
	ID         string                `json:"id"`
	Transports []CredentialTransport `json:"transports"`
}

type AllowCredentials struct {
	Key      []AllowCredential `json:"key"`
	Webauthn []AllowCredential `json:"webauthn"`
}

// For not it returns a KeyAssertion. But we can make it more generic afterward
type ICredentialSigner interface {
	Sign(challenge string, allowCredential *AllowCredentials) (*KeyAssertion, error)
}
