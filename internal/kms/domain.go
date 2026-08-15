package kms

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Domain is the key material of one security domain: the root certificate
// a KMS publishes (TS 33.180 clause 5.3.5) and the master secrets behind
// it, from which every user's key set (clause 5.3.6) is derived.
type Domain struct {
	// KMSURI identifies the domain and is hashed into every UID, so it
	// cannot change without invalidating all issued key material.
	KMSURI string
	// CertURI names this certificate. Clause 5.3.5: a client replaces an
	// existing certificate when it receives one with the same CertUri.
	CertURI string
	Issuer  string

	Period KeyPeriod

	// ValidFrom and ValidTo bound the certificate itself.
	ValidFrom time.Time
	ValidTo   time.Time

	// DomainList is the optional list of domains the certificate covers.
	DomainList []string

	sakke *SAKKEKeyPair
	eccsi *ECCSIKeyPair
}

// masterSecretFile is the on-disk form of the domain's private key
// material. It is deliberately minimal and deliberately not part of the
// YAML configuration: these are the secrets from which every user key in
// the domain is derived, and a configuration file is the wrong place for
// them.
//
// The format is one "name = hex" assignment per line so an operator can
// see what a file holds without a tool.
const (
	sakkeMasterLabel = "sakke_master_secret"
	eccsiMasterLabel = "eccsi_ksak"
)

// LoadDomain reads the domain's master secrets from path, generating a
// fresh pair if the file does not exist yet. The file is created with
// owner-only permissions, and a file that is readable beyond its owner is
// reported rather than silently accepted.
func LoadDomain(path string, d Domain) (*Domain, error) {
	if strings.TrimSpace(d.KMSURI) == "" {
		return nil, errors.New("kms: a KMS URI is required")
	}
	if err := d.Period.Validate(); err != nil {
		return nil, fmt.Errorf("kms: key period: %w", err)
	}

	secrets, err := readMasterSecrets(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if secrets, err = generateMasterSecrets(path); err != nil {
			return nil, err
		}
		slog.Warn("KMS domain key material generated; back it up before provisioning clients",
			"path", path, "kms_uri", d.KMSURI)
	case err != nil:
		return nil, err
	}

	if d.sakke, err = NewSAKKEKeyPair(secrets[sakkeMasterLabel]); err != nil {
		return nil, fmt.Errorf("kms: SAKKE master secret: %w", err)
	}
	if d.eccsi, err = NewECCSIKeyPair(secrets[eccsiMasterLabel]); err != nil {
		return nil, fmt.Errorf("kms: ECCSI KSAK: %w", err)
	}
	if strings.TrimSpace(d.CertURI) == "" {
		d.CertURI = "cert1." + d.KMSURI
	}
	return &d, nil
}

func readMasterSecrets(path string) (map[string]*big.Int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Windows does not carry POSIX permission bits, so Go reports a mode
	// that says nothing about who can read the file; the check would
	// reject every file there.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("kms: %s is readable beyond its owner (mode %#o)", path, perm)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	secrets := map[string]*big.Int{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("kms: malformed line in %s", path)
		}
		digits, err := hex.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("kms: %s in %s is not hexadecimal", strings.TrimSpace(name), path)
		}
		secrets[strings.TrimSpace(name)] = new(big.Int).SetBytes(digits)
	}
	for _, want := range []string{sakkeMasterLabel, eccsiMasterLabel} {
		if secrets[want] == nil {
			return nil, fmt.Errorf("kms: %s is missing %s", path, want)
		}
	}
	return secrets, nil
}

func generateMasterSecrets(path string) (map[string]*big.Int, error) {
	sakkePair, err := GenerateSAKKEKeyPair()
	if err != nil {
		return nil, err
	}
	eccsiPair, err := GenerateECCSIKeyPair()
	if err != nil {
		return nil, err
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("kms: key material directory: %w", err)
		}
	}
	body := strings.Join([]string{
		"# VectorCore MCX KMS domain key material (TS 33.180 clause 5.3).",
		"# Every user key in this domain derives from these two secrets.",
		sakkeMasterLabel + " = " + hex.EncodeToString(sakkePair.Master.Bytes()),
		eccsiMasterLabel + " = " + hex.EncodeToString(eccsiPair.Secret.Bytes()),
		"",
	}, "\n")

	// O_EXCL so a concurrent start cannot overwrite key material that
	// clients may already have been provisioned against.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("kms: create key material: %w", err)
	}
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return map[string]*big.Int{
		sakkeMasterLabel: sakkePair.Master,
		eccsiMasterLabel: eccsiPair.Secret,
	}, nil
}

// Certificate builds the domain's root KMS certificate.
func (d *Domain) Certificate() (*KmsCertificate, error) {
	enc, err := d.sakke.PublicKey()
	if err != nil {
		return nil, err
	}
	cert := &KmsCertificate{
		Version: certificateVersion,
		Role:    "Root",
		CertURI: d.CertURI,
		KMSURI:  d.KMSURI,
		Issuer:  d.Issuer,
		Revoked: boolPtr(false),
		// Clause 5.3.5 / table D.3.2.2-1: the value '2' selects the UID
		// generation mechanism of clause F.2.1.
		UserIDFormat:  "2",
		UserKeyPeriod: d.Period.LengthSeconds,
		UserKeyOffset: d.Period.OffsetSeconds,
		PubEncKey:     strings.ToUpper(hex.EncodeToString(enc)),
		PubAuthKey:    strings.ToUpper(hex.EncodeToString(d.eccsi.Public)),
		ParameterSet:  ParameterSet1,
	}
	if !d.ValidFrom.IsZero() {
		cert.ValidFrom = xsdDateTime(d.ValidFrom)
	}
	if !d.ValidTo.IsZero() {
		cert.ValidTo = xsdDateTime(d.ValidTo)
	}
	if len(d.DomainList) > 0 {
		cert.DomainList = &KmsDomainList{Domain: d.DomainList}
	}
	return cert, nil
}

// KeySet derives the key material of one identity for one key period
// (TS 33.180 clause 5.3.6). The identity is an MC service ID such as an
// MCPTT ID; the UID that the keys are bound to is derived from it, the
// KMS URI and the key period.
func (d *Domain) KeySet(identity string, at time.Time) (*KmsKeySet, error) {
	uid, number, err := UIDAt(identity, d.KMSURI, d.Period, at)
	if err != nil {
		return nil, err
	}
	return d.keySetForPeriod(identity, uid, number)
}

// KeySetForPeriod derives key material for an explicit key period number,
// which is what a keyprov request carrying a specific time asks for
// (clause D.2.4).
func (d *Domain) KeySetForPeriod(identity string, number int64) (*KmsKeySet, error) {
	uid, err := UID(identity, d.KMSURI, d.Period, number)
	if err != nil {
		return nil, err
	}
	return d.keySetForPeriod(identity, uid, number)
}

func (d *Domain) keySetForPeriod(identity string, uid []byte, number int64) (*KmsKeySet, error) {
	rsk, err := d.sakke.ReceiverSecretKey(uid)
	if err != nil {
		return nil, err
	}
	signing, err := d.eccsi.NewSigningKey(uid)
	if err != nil {
		return nil, err
	}
	// The KMS validates its own output before releasing it. Both checks
	// are the ones the receiving client runs, so a domain whose key
	// material has been corrupted fails here rather than silently
	// provisioning keys that no client can use.
	if err := d.sakke.ValidateReceiverSecretKey(uid, rsk); err != nil {
		return nil, err
	}
	if err := d.eccsi.ValidateSigningKey(uid, signing); err != nil {
		return nil, err
	}

	from, to := d.Period.Bounds(number)
	return &KmsKeySet{
		Version:     keySetVersion,
		KMSURI:      d.KMSURI,
		CertURI:     d.CertURI,
		Issuer:      d.Issuer,
		UserURI:     identity,
		UserID:      base64Std(uid),
		ValidFrom:   xsdDateTime(from),
		ValidTo:     xsdDateTime(to.Add(-time.Second)),
		KeyPeriodNo: number,
		Revoked:     boolPtr(false),
		DecryptKey:  hexKey(rsk),
		SigningKey:  hexKey(signing.SSK),
		PubToken:    hexKey(signing.PVT),
	}, nil
}
