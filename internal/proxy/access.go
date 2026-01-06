package proxy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	errClientRevoked    = errors.New("client certificate revoked")
	errClientNotAllowed = errors.New("client certificate not allowed")
)

type AccessPolicyConfig struct {
	AllowedCN          []string
	AllowedDNS         []string
	AllowedURI         []string
	AllowedURIPrefixes []string
	RevokedFP          []string
}

type AccessPolicy struct {
	allowedCN          map[string]struct{}
	allowedDNS         map[string]struct{}
	allowedURI         map[string]struct{}
	allowedURIPrefixes []string
	revokedFP          map[string]struct{}
	allowAll           bool
}

type ClientIdentity struct {
	Subject     string
	Serial      string
	Fingerprint string
}

func NewAccessPolicy(cfg AccessPolicyConfig) *AccessPolicy {
	allowedCN := toLowerSet(cfg.AllowedCN)
	allowedDNS := toLowerSet(cfg.AllowedDNS)
	allowedURI := toExactSet(cfg.AllowedURI)
	allowedURIPrefixes := toTrimmedList(cfg.AllowedURIPrefixes)
	revokedFP := toFingerprintSet(cfg.RevokedFP)

	allowAll := len(allowedCN) == 0 && len(allowedDNS) == 0 && len(allowedURI) == 0 && len(allowedURIPrefixes) == 0

	return &AccessPolicy{
		allowedCN:          allowedCN,
		allowedDNS:         allowedDNS,
		allowedURI:         allowedURI,
		allowedURIPrefixes: allowedURIPrefixes,
		revokedFP:          revokedFP,
		allowAll:           allowAll,
	}
}

func (p *AccessPolicy) Authorize(cert *x509.Certificate) (ClientIdentity, error) {
	identity := buildIdentity(cert)
	if _, revoked := p.revokedFP[identity.Fingerprint]; revoked {
		return identity, errClientRevoked
	}
	if p.allowAll {
		return identity, nil
	}
	if p.matches(cert) {
		return identity, nil
	}
	return identity, errClientNotAllowed
}

func (p *AccessPolicy) matches(cert *x509.Certificate) bool {
	cn := strings.ToLower(strings.TrimSpace(cert.Subject.CommonName))
	if cn != "" {
		if _, ok := p.allowedCN[cn]; ok {
			return true
		}
	}

	if len(p.allowedDNS) > 0 {
		for _, name := range cert.DNSNames {
			if _, ok := p.allowedDNS[strings.ToLower(name)]; ok {
				return true
			}
		}
	}

	if len(p.allowedURI) > 0 || len(p.allowedURIPrefixes) > 0 {
		for _, uri := range cert.URIs {
			if uri == nil {
				continue
			}
			value := uri.String()
			if _, ok := p.allowedURI[value]; ok {
				return true
			}
			for _, prefix := range p.allowedURIPrefixes {
				if strings.HasPrefix(value, prefix) {
					return true
				}
			}
		}
	}

	return false
}

func buildIdentity(cert *x509.Certificate) ClientIdentity {
	fingerprint := ""
	if cert != nil {
		sum := sha256.Sum256(cert.Raw)
		fingerprint = hex.EncodeToString(sum[:])
	}
	return ClientIdentity{
		Subject:     cert.Subject.String(),
		Serial:      cert.SerialNumber.String(),
		Fingerprint: fingerprint,
	}
}

func toLowerSet(values []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}

func toExactSet(values []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}

func toTrimmedList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func toFingerprintSet(values []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, value := range values {
		normalized := normalizeFingerprint(value)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}

func normalizeFingerprint(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ":", "")
	value = strings.ReplaceAll(value, " ", "")
	return strings.ToLower(value)
}
