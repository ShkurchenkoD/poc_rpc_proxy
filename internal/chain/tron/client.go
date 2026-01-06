package tron

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"poc_rpc_proxy/internal/chain"
)

const maxResponseBytes = 8 << 20

var (
	ErrInvalidAddress = errors.New("invalid tron address")
	ErrInvalidTxID    = errors.New("invalid tron txid")
	ErrInvalidTx      = errors.New("invalid tron transaction")
)

type Client struct {
	baseURLs    []string
	http        *http.Client
	maxAttempts int
	rng         *rand.Rand
	rngMu       sync.Mutex
}

func NewClient(baseURLs []string, timeout time.Duration, maxAttempts int) (*Client, error) {
	baseURLs = normalizeBaseURLs(baseURLs)
	if len(baseURLs) == 0 {
		return nil, errors.New("tron base url is required")
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	return &Client{
		baseURLs:    baseURLs,
		http:        &http.Client{Timeout: timeout},
		maxAttempts: maxAttempts,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

func (c *Client) GetBalance(ctx context.Context, address string) (chain.BalanceResult, error) {
	hexAddr, err := normalizeAddress(address)
	if err != nil {
		return chain.BalanceResult{}, ErrInvalidAddress
	}
	payload := map[string]string{
		"address": hexAddr,
	}
	raw, err := c.post(ctx, "/wallet/getaccount", payload)
	if err != nil {
		return chain.BalanceResult{}, err
	}

	return chain.BalanceResult{
		Chain:    "tron",
		Address:  address,
		Balance:  numberString(raw["balance"]),
		Unit:     "sun",
		Decimals: 6,
		Raw:      raw,
	}, nil
}

func (c *Client) GetTransaction(ctx context.Context, txid string) (chain.TransactionResult, error) {
	txid = strings.TrimSpace(txid)
	if txid == "" {
		return chain.TransactionResult{}, ErrInvalidTxID
	}
	payload := map[string]string{
		"value": txid,
	}
	raw, err := c.post(ctx, "/wallet/gettransactionbyid", payload)
	if err != nil {
		return chain.TransactionResult{}, err
	}

	return chain.TransactionResult{
		Chain: "tron",
		TxID:  txid,
		Raw:   raw,
	}, nil
}

func (c *Client) SendRawTransaction(ctx context.Context, tx map[string]any) (chain.SendResult, error) {
	if len(tx) == 0 {
		return chain.SendResult{}, ErrInvalidTx
	}
	raw, err := c.post(ctx, "/wallet/broadcasttransaction", tx)
	if err != nil {
		return chain.SendResult{}, err
	}

	return chain.SendResult{
		Chain:   "tron",
		TxID:    stringValue(raw["txid"]),
		Success: boolValue(raw["result"]),
		Raw:     raw,
	}, nil
}

func (c *Client) GetAccountResource(ctx context.Context, address string) (chain.ResourceResult, error) {
	hexAddr, err := normalizeAddress(address)
	if err != nil {
		return chain.ResourceResult{}, ErrInvalidAddress
	}
	payload := map[string]string{
		"address": hexAddr,
	}
	raw, err := c.post(ctx, "/wallet/getaccountresource", payload)
	if err != nil {
		return chain.ResourceResult{}, err
	}

	return chain.ResourceResult{
		Chain:        "tron",
		Address:      address,
		EnergyLimit:  numberString(raw["EnergyLimit"]),
		EnergyUsed:   numberString(raw["EnergyUsed"]),
		NetLimit:     numberString(raw["NetLimit"]),
		NetUsed:      numberString(raw["NetUsed"]),
		FreeNetLimit: numberString(raw["freeNetLimit"]),
		FreeNetUsed:  numberString(raw["freeNetUsed"]),
		Raw:          raw,
	}, nil
}

func (c *Client) post(ctx context.Context, path string, payload any) (map[string]any, error) {
	if len(c.baseURLs) == 0 {
		return nil, errors.New("tron base url is required")
	}
	body, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	attempts := c.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	ordered := c.shuffledBaseURLs()

	var lastErr error
	var lastResp map[string]any
	for i := 0; i < attempts; i++ {
		if i > 0 && len(ordered) > 1 && i%len(ordered) == 0 {
			ordered = c.shuffledBaseURLs()
		}
		baseURL := ordered[i%len(ordered)]
		resp, err := c.postOnce(ctx, baseURL, path, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		lastResp = resp
		if ctx.Err() != nil {
			return lastResp, ctx.Err()
		}
	}
	return lastResp, lastErr
}

func (c *Client) postOnce(ctx context.Context, baseURL, path string, body []byte) (map[string]any, error) {
	url := baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if len(respBody) == 0 {
		return nil, fmt.Errorf("empty response from tron upstream")
	}

	dec := json.NewDecoder(bytes.NewReader(respBody))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}

	outMap, ok := out.(map[string]any)
	if !ok {
		outMap = map[string]any{"value": out}
	}

	if resp.StatusCode >= 400 {
		return outMap, fmt.Errorf("tron upstream status %d", resp.StatusCode)
	}
	return outMap, nil
}

func encodePayload(payload any) ([]byte, error) {
	if payload == nil {
		return nil, nil
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalizeBaseURLs(baseURLs []string) []string {
	out := make([]string, 0, len(baseURLs))
	for _, baseURL := range baseURLs {
		baseURL = strings.TrimSpace(baseURL)
		if baseURL == "" {
			continue
		}
		baseURL = strings.TrimRight(baseURL, "/")
		if baseURL == "" {
			continue
		}
		out = append(out, baseURL)
	}
	return out
}

func (c *Client) shuffledBaseURLs() []string {
	urls := make([]string, len(c.baseURLs))
	copy(urls, c.baseURLs)
	if len(urls) < 2 {
		return urls
	}
	c.rngMu.Lock()
	c.rng.Shuffle(len(urls), func(i, j int) {
		urls[i], urls[j] = urls[j], urls[i]
	})
	c.rngMu.Unlock()
	return urls
}

func numberString(value any) string {
	switch v := value.(type) {
	case json.Number:
		return v.String()
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case int:
		return fmt.Sprintf("%d", v)
	case string:
		if v == "" {
			return "0"
		}
		return v
	default:
		return "0"
	}
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func boolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.ToLower(v) == "true"
	default:
		return false
	}
}
