package wallet

import (
	"regexp"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Certificate is a placeholder for the certificate data structure
type Certificate struct {
	// Type is the type of certificate
	Type string `json:"type"`
	// Subject is the subject of the certificate
	Subject string `json:"subject"`
	// SerialNumber is the serial number of the certificate
	SerialNumber string `json:"serialNumber"`
	// Certifier is the certifier of the certificate
	Certifier string `json:"certifier"`
	// RevocationOutpoint is the revocation outpoint of the certificate
	RevocationOutpoint string `json:"revocationOutpoint"`
	// Fields is the map representing custom fields of the certificate (payload)
	Fields map[string]any `json:"fields"`
	// Signature is the signature of the certificate
	Signature string `json:"signature"`
}

// GetPublicKeyOptions defines parameters for GetPublicKey
type GetPublicKeyOptions struct {
	// IdentityKey is a flag to return the identity key
	IdentityKey bool `json:"identityKey"`
	// ProtocolID is the protocol ID for the key
	ProtocolID any `json:"protocolID,omitempty"`
	// KeyID is the key ID for the key
	KeyID string `json:"keyID,omitempty"`
	// Counterparty is the counterparty for the key
	Counterparty string `json:"counterparty,omitempty"`
	// Privileged is a flag to return a privileged key
	Privileged bool `json:"privileged,omitempty"`
	// ForSelf is a flag to return a key for self
	ForSelf bool `json:"forSelf,omitempty"`
}

// EncryptionArgs base struct with common arguments for encryption operations
type EncryptionArgs struct {
	ProtocolID       Protocol
	KeyID            string
	Counterparty     Counterparty
	Privileged       bool
	PrivilegedReason string
	SeekPermission   bool
}

// GetPublicKeyArgs defines parameters for GetPublicKey
type GetPublicKeyArgs struct {
	EncryptionArgs
	IdentityKey bool
	ForSelf     bool
}

// GetPublicKeyResult defines the result of GetPublicKey
type GetPublicKeyResult struct {
	PublicKey *ec.PublicKey `json:"publicKey"`
}

// CreateSignatureArgs defines parameters for CreateSignature
type CreateSignatureArgs struct {
	EncryptionArgs
	Data               []byte
	DashToDirectlySign []byte
}

// CreateSignatureResult defines the result of CreateSignature
type CreateSignatureResult struct {
	Signature ec.Signature
}

// VerifySignatureArgs defines parameters for VerifySignature
type VerifySignatureArgs struct {
	EncryptionArgs
	Data                 []byte
	HashToDirectlyVerify []byte
	Signature            ec.Signature
	ForSelf              bool
}

// VerifySignatureResult defines the result of VerifySignature
type VerifySignatureResult struct {
	Valid bool
}

// SecurityLevel defines the access control level for wallet operations.
// It determines how strictly the wallet enforces user confirmation for operations.
type SecurityLevel int

// Security levels
var (
	SecurityLevelSilent                  SecurityLevel = 0
	SecurityLevelEveryApp                SecurityLevel = 1
	SecurityLevelEveryAppAndCounterparty SecurityLevel = 2
)

// Protocol defines a protocol with its security level and name.
// The security level determines how strictly the wallet enforces user confirmation.
type Protocol struct {
	SecurityLevel SecurityLevel
	Protocol      string
}

// Protocols with their respective security levels
var (
	// DefaultAuthProtocol is the default protocol for authentication messages.
	DefaultAuthProtocol = Protocol{SecurityLevel: SecurityLevelEveryAppAndCounterparty, Protocol: "auth message signature"}
)

// CounterpartyType defines the type of counterparty for operation.
type CounterpartyType int

const (
	// CounterpartyTypeAnyone is used when the counterparty is anyone.
	CounterpartyTypeAnyone CounterpartyType = 1
	// CounterpartyTypeSelf is used when the counterparty is self.
	CounterpartyTypeSelf CounterpartyType = 2
	// CounterpartyTypeOther is used when the counterparty is other.
	CounterpartyTypeOther CounterpartyType = 3
)

// Counterparty represents a counterparty in a protocol.
type Counterparty struct {
	Type         CounterpartyType
	Counterparty *ec.PublicKey
}

var regexOnlyLettersNumbersSpaces = regexp.MustCompile(`^[a-z0-9 ]+$`)
