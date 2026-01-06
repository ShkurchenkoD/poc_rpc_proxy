package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"poc_rpc_proxy/internal/chain/tron"
	"poc_rpc_proxy/internal/proxy"
)

type config struct {
	Addr            string
	TronURLs        []string
	TronMaxAttempts int
	Timeout         time.Duration
	TLSCertPath     string
	TLSKeyPath      string
	TLSClientCA     string
	AllowedFile     string
	RevokedFile     string
}

func main() {
	cfg := loadConfig()

	tronClient, err := tron.NewClient(cfg.TronURLs, cfg.Timeout, cfg.TronMaxAttempts)
	if err != nil {
		log.Fatalf("tron client: %v", err)
	}

	accessPolicy, err := loadAccessPolicy(cfg)
	if err != nil {
		log.Fatalf("access policy: %v", err)
	}

	handler := proxy.NewServer(tronClient, cfg.Timeout, accessPolicy)

	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         tlsCfg,
	}

	log.Printf("rpc proxy listening on https://%s", cfg.Addr)
	if err := server.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() config {
	addr := getenv("PROXY_ADDR", ":8080")
	tronURLs := splitListEnv(os.Getenv("TRON_RPC_URLS"))
	if len(tronURLs) == 0 {
		tronURLs = []string{getenv("TRON_RPC_URL", "http://127.0.0.1:8090")}
	}
	tronMaxAttempts := parseMaxAttempts(getenv("TRON_RPC_MAX_ATTEMPTS", "3"))
	timeout := parseTimeout(getenv("PROXY_TIMEOUT_MS", "8000"))
	tlsCert := os.Getenv("PROXY_TLS_CERT")
	tlsKey := os.Getenv("PROXY_TLS_KEY")
	tlsClientCA := os.Getenv("PROXY_TLS_CLIENT_CA")
	allowedFile := os.Getenv("PROXY_TLS_ALLOWED_FILE")
	revokedFile := os.Getenv("PROXY_TLS_REVOKED_FILE")

	if tlsCert == "" || tlsKey == "" || tlsClientCA == "" {
		log.Fatal("PROXY_TLS_CERT, PROXY_TLS_KEY, and PROXY_TLS_CLIENT_CA are required")
	}

	return config{
		Addr:            addr,
		TronURLs:        tronURLs,
		TronMaxAttempts: tronMaxAttempts,
		Timeout:         timeout,
		TLSCertPath:     tlsCert,
		TLSKeyPath:      tlsKey,
		TLSClientCA:     tlsClientCA,
		AllowedFile:     allowedFile,
		RevokedFile:     revokedFile,
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func parseTimeout(value string) time.Duration {
	ms, err := strconv.Atoi(value)
	if err != nil || ms <= 0 {
		return 8 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

func parseMaxAttempts(value string) int {
	attempts, err := strconv.Atoi(value)
	if err != nil || attempts <= 0 {
		return 3
	}
	return attempts
}

func splitListEnv(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func loadTLSConfig(cfg config) (*tls.Config, error) {
	caPEM, err := os.ReadFile(cfg.TLSClientCA)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, errInvalidClientCA
	}

	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
}

var errInvalidClientCA = errors.New("invalid client CA PEM")

func loadAccessPolicy(cfg config) (*proxy.AccessPolicy, error) {
	policyCfg := proxy.AccessPolicyConfig{}

	if cfg.AllowedFile != "" {
		allowedCfg, err := parseAllowlistFile(cfg.AllowedFile)
		if err != nil {
			return nil, err
		}
		policyCfg.AllowedCN = append(policyCfg.AllowedCN, allowedCfg.AllowedCN...)
		policyCfg.AllowedDNS = append(policyCfg.AllowedDNS, allowedCfg.AllowedDNS...)
		policyCfg.AllowedURI = append(policyCfg.AllowedURI, allowedCfg.AllowedURI...)
		policyCfg.AllowedURIPrefixes = append(policyCfg.AllowedURIPrefixes, allowedCfg.AllowedURIPrefixes...)
	}

	if cfg.RevokedFile != "" {
		revoked, err := parseRevokedFile(cfg.RevokedFile)
		if err != nil {
			return nil, err
		}
		policyCfg.RevokedFP = append(policyCfg.RevokedFP, revoked...)
	}

	return proxy.NewAccessPolicy(policyCfg), nil
}

func parseAllowlistFile(path string) (proxy.AccessPolicyConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return proxy.AccessPolicyConfig{}, err
	}
	defer file.Close()

	cfg := proxy.AccessPolicyConfig{}
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return proxy.AccessPolicyConfig{}, fmt.Errorf("allowlist %s:%d: invalid entry", path, lineNo)
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		switch key {
		case "cn":
			cfg.AllowedCN = append(cfg.AllowedCN, value)
		case "dns":
			cfg.AllowedDNS = append(cfg.AllowedDNS, value)
		case "uri":
			cfg.AllowedURI = append(cfg.AllowedURI, value)
		case "uri_prefix":
			cfg.AllowedURIPrefixes = append(cfg.AllowedURIPrefixes, value)
		default:
			return proxy.AccessPolicyConfig{}, fmt.Errorf("allowlist %s:%d: unknown key %q", path, lineNo, key)
		}
	}

	if err := scanner.Err(); err != nil {
		return proxy.AccessPolicyConfig{}, err
	}
	return cfg, nil
}

func parseRevokedFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var revoked []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		revoked = append(revoked, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return revoked, nil
}
