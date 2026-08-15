package kms

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"strings"
	"time"
)

// The KMS interface XML of TS 33.180 Annex D, following the base schema
// of clause D.3.5.1. Element order matters: the schema declares
// xsd:sequence throughout, so the field order below is the schema's.

const (
	xsiNamespace       = "http://www.w3.org/2001/XMLSchema-instance"
	responseVer        = "1.0.0"
	requestVer         = "1.1.0"
	messageVer         = "1.0.0"
	certificateVersion = "1.1.0"
	keySetVersion      = "1.1.0"
)

// KmsRequest is the request payload of clause D.2.2. Only the fields the
// server acts on are parsed; the schema permits extension elements in
// other namespaces, which are ignored as it intends.
type KmsRequest struct {
	XMLName      xml.Name `xml:"KmsRequest"`
	Version      string   `xml:"Version,attr"`
	UserURI      string   `xml:"UserUri"`
	KMSURI       string   `xml:"KmsUri"`
	Time         string   `xml:"Time"`
	ClientID     string   `xml:"ClientId,omitempty"`
	DeviceID     string   `xml:"DeviceId,omitempty"`
	ClientReqURL string   `xml:"ClientReqUrl"`
}

// SignedKmsRequest wraps a request with its XML signature. The signature
// itself is the security extension of clause D.2.2, which is not applied
// here; the wrapper is parsed so a client that sends one is still
// understood.
type SignedKmsRequest struct {
	XMLName xml.Name    `xml:"SignedKmsRequest"`
	Request *KmsRequest `xml:"KmsRequest"`
}

// KmsResponse is the response of table D.3.1-1.
type KmsResponse struct {
	XMLName      xml.Name    `xml:"urn:3gpp:ns:mcsecKMSInterface:1.0 KmsResponse"`
	XSI          string      `xml:"xmlns:xsi,attr"`
	Version      string      `xml:"Version,attr"`
	UserURI      string      `xml:"UserUri"`
	KMSURI       string      `xml:"KmsUri"`
	Time         string      `xml:"Time"`
	KMSID        string      `xml:"KmsId,omitempty"`
	ClientReqURL string      `xml:"ClientReqUrl"`
	Message      *KmsMessage `xml:"KmsMessage,omitempty"`
	Error        *KmsError   `xml:"KmsError,omitempty"`
}

// KmsMessage carries exactly one of the response bodies (schema type
// KMSMessage, an xsd:choice).
type KmsMessage struct {
	Init      *KmsInit      `xml:"KmsInit,omitempty"`
	KeyProv   *KmsKeyProv   `xml:"KmsKeyProv,omitempty"`
	CertCache *KmsCertCache `xml:"KmsCertCache,omitempty"`
}

// KmsError is the ErrorType of clause D.3.5.1, used when the KMS cannot
// satisfy a request (for instance a Cert request for a certificate it
// does not hold).
type KmsError struct {
	Code    int    `xml:"ErrorCode"`
	Message string `xml:"ErrorMsg"`
}

// KmsInit is the response to a KMS Initialize request: the root
// certificate of the domain.
type KmsInit struct {
	Version     string          `xml:"Version,attr"`
	Certificate *KmsCertificate `xml:"KmsCertificate"`
}

// KmsKeyProv is the response to a KMS KeyProvision request: zero or more
// key sets.
type KmsKeyProv struct {
	Version string      `xml:"Version,attr"`
	KeySets []KmsKeySet `xml:"KmsKeySet"`
}

// KmsCertCache is the response to a CertCache or Cert request. CacheNum
// lets a client tell the KMS which version it already holds.
type KmsCertCache struct {
	Version      string           `xml:"Version,attr"`
	CacheNum     int              `xml:"CacheNum,attr,omitempty"`
	Certificates []KmsCertificate `xml:"KmsCertificate"`
}

// KmsCertificate is the certificate of table D.3.2.2-1.
type KmsCertificate struct {
	Version string `xml:"Version,attr"`
	Role    string `xml:"Role,attr"`

	CertURI       string         `xml:"CertUri,omitempty"`
	KMSURI        string         `xml:"KmsUri"`
	Issuer        string         `xml:"Issuer,omitempty"`
	ValidFrom     string         `xml:"ValidFrom,omitempty"`
	ValidTo       string         `xml:"ValidTo,omitempty"`
	Revoked       *bool          `xml:"Revoked,omitempty"`
	UserIDFormat  string         `xml:"UserIdFormat"`
	UserKeyPeriod int64          `xml:"UserKeyPeriod"`
	UserKeyOffset int64          `xml:"UserKeyOffset"`
	PubEncKey     string         `xml:"PubEncKey"`
	PubAuthKey    string         `xml:"PubAuthKey"`
	ParameterSet  int            `xml:"ParameterSet,omitempty"`
	DomainList    *KmsDomainList `xml:"KmsDomainList,omitempty"`
}

type KmsDomainList struct {
	Domain []string `xml:"KmsDomain"`
}

// KmsKeySet is the key set of table D.3.3.2-1.
type KmsKeySet struct {
	Version string `xml:"Version,attr"`

	KMSURI      string      `xml:"KmsUri"`
	CertURI     string      `xml:"CertUri,omitempty"`
	Issuer      string      `xml:"Issuer,omitempty"`
	UserURI     string      `xml:"UserUri"`
	UserID      string      `xml:"UserID"`
	ValidFrom   string      `xml:"ValidFrom,omitempty"`
	ValidTo     string      `xml:"ValidTo,omitempty"`
	KeyPeriodNo int64       `xml:"KeyPeriodNo"`
	Revoked     *bool       `xml:"Revoked,omitempty"`
	DecryptKey  *KeyContent `xml:"UserDecryptKey"`
	SigningKey  *KeyContent `xml:"UserSigningKeySSK"`
	PubToken    *KeyContent `xml:"UserPubTokenPVT"`
}

// KeyContent is the KeyContentType of clause D.3.5.1: key material as
// hexBinary, carried directly. The alternative, EncKeyContentType, wraps
// the material in an XML-encrypted key under the shared TrK; that is the
// security extension of clause D.2.2 and is not applied here, so the
// confidentiality of this material rests entirely on the HTTPS
// connection of clause D.1.
//
// The type attribute is written with the literal "xsi:" prefix that the
// examples of clause D.3.4 use, which the response element declares. Go's
// encoder invents its own prefix when asked for a namespaced attribute,
// and a machine-generated prefix is needlessly hard for an operator to
// read against the specification.
type KeyContent struct {
	Type  string `xml:"xsi:type,attr"`
	Value string `xml:",chardata"`
}

func hexKey(b []byte) *KeyContent {
	return &KeyContent{Type: "KeyContentType", Value: strings.ToUpper(hex.EncodeToString(b))}
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func boolPtr(v bool) *bool { return &v }

// xsdDateTime renders an instant as the xsd:dateTime the schema expects.
// The examples of clause D.3.4 carry no zone designator, but a bare local
// time is ambiguous, so UTC is stated explicitly.
func xsdDateTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// Marshal renders a response with the XML declaration clients expect.
func (r *KmsResponse) Marshal() ([]byte, error) {
	r.XSI = xsiNamespace
	body, err := xml.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

// DecodeUserID decodes the base64 UID of a KmsKeySet's UserID field.
func DecodeUserID(v string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(v))
}

// DecodeKeyContent decodes the hexBinary of a KeyContentType element.
// It refuses an element carrying encrypted key material, because the
// caller would otherwise treat ciphertext as a key.
func DecodeKeyContent(k *KeyContent) ([]byte, error) {
	if k == nil {
		return nil, errors.New("the key element is absent")
	}
	if t := strings.TrimSpace(k.Type); t != "" && t != "KeyContentType" {
		return nil, errors.New("the key is carried as " + t + ", not as plain hexBinary")
	}
	return DecodeHex(k.Value)
}

// DecodeHex decodes an xsd:hexBinary value, tolerating either case.
func DecodeHex(v string) ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(v))
}
