package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"poc_rpc_proxy/internal/chain/tron"
	"poc_rpc_proxy/internal/jsonrpc"
)

const maxBodyBytes = 2 << 20

type Server struct {
	tron    *tron.Client
	timeout time.Duration
	access  *AccessPolicy
}

func NewServer(tronClient *tron.Client, timeout time.Duration, access *AccessPolicy) *Server {
	if access == nil {
		access = NewAccessPolicy(AccessPolicyConfig{})
	}
	return &Server{
		tron:    tronClient,
		timeout: timeout,
		access:  access,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, jsonrpc.ErrorResponse(json.RawMessage("null"), jsonrpc.InvalidRequest, "client certificate required", nil))
		return
	}

	identity, err := s.access.Authorize(r.TLS.PeerCertificates[0])
	if err != nil {
		status := http.StatusForbidden
		message := "client certificate not allowed"
		if errors.Is(err, errClientRevoked) {
			message = "client certificate revoked"
		} else if !errors.Is(err, errClientNotAllowed) {
			status = http.StatusUnauthorized
			message = "client certificate rejected"
		}
		log.Printf("deny reason=%s client_subject=%q client_serial=%s client_fingerprint=%s", err.Error(), identity.Subject, identity.Serial, identity.Fingerprint)
		w.WriteHeader(status)
		writeJSON(w, jsonrpc.ErrorResponse(json.RawMessage("null"), jsonrpc.InvalidRequest, message, nil))
		return
	}

	ctx := withClientIdentity(r.Context(), identity)
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeJSON(w, jsonrpc.ErrorResponse(json.RawMessage("null"), jsonrpc.ParseError, "read error", nil))
		return
	}
	if len(body) > maxBodyBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	reqs, isBatch, err := jsonrpc.DecodeRequests(body)
	if err != nil {
		code := jsonrpc.ParseError
		message := "parse error"
		if errors.Is(err, jsonrpc.ErrEmptyBatch) {
			code = jsonrpc.InvalidRequest
			message = "invalid request"
		}
		writeJSON(w, jsonrpc.ErrorResponse(json.RawMessage("null"), code, message, nil))
		return
	}

	if isBatch {
		responses := s.handleBatch(ctx, reqs)
		if len(responses) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, responses)
		return
	}

	resp := s.handleSingle(ctx, reqs[0])
	if resp == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleBatch(ctx context.Context, reqs []jsonrpc.Request) []*jsonrpc.Response {
	responses := make([]*jsonrpc.Response, len(reqs))
	var wg sync.WaitGroup

	for i, req := range reqs {
		if jsonrpc.IsNotification(req) {
			continue
		}
		wg.Add(1)
		go func(idx int, r jsonrpc.Request) {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			responses[idx] = s.handleRequest(reqCtx, r)
		}(i, req)
	}

	wg.Wait()
	return filterResponses(responses)
}

func (s *Server) handleSingle(ctx context.Context, req jsonrpc.Request) *jsonrpc.Response {
	if jsonrpc.IsNotification(req) {
		return nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.handleRequest(reqCtx, req)
}

func (s *Server) handleRequest(ctx context.Context, req jsonrpc.Request) *jsonrpc.Response {
	if err := jsonrpc.ValidateRequest(req); err != nil {
		return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidRequest, err.Error(), nil)
	}

	start := time.Now()
	resp := s.dispatch(ctx, req)
	clientSubject, clientSerial, clientFingerprint := clientIdentityFromContext(ctx)
	log.Printf(
		"method=%s duration_ms=%d error=%t client_subject=%q client_serial=%s client_fingerprint=%s",
		req.Method,
		time.Since(start).Milliseconds(),
		resp.Error != nil,
		clientSubject,
		clientSerial,
		clientFingerprint,
	)
	return resp
}

type balanceParams struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

type transactionParams struct {
	Chain string `json:"chain"`
	TxID  string `json:"txid"`
}

type sendParams struct {
	Chain string         `json:"chain"`
	Tx    map[string]any `json:"tx"`
}

type resourceParams struct {
	Address string `json:"address"`
}

func (s *Server) dispatch(ctx context.Context, req jsonrpc.Request) *jsonrpc.Response {
	switch req.Method {
	case "getBalance":
		var p balanceParams
		if err := jsonrpc.UnmarshalParams(req.Params, &p); err != nil {
			return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidParams, "invalid params", err.Error())
		}
		chainName := normalizeChain(p.Chain)
		if chainName != "tron" {
			return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidParams, "unsupported chain", nil)
		}
		result, err := s.tron.GetBalance(ctx, p.Address)
		return respondChain(req.ID, result, err)
	case "getTransaction":
		var p transactionParams
		if err := jsonrpc.UnmarshalParams(req.Params, &p); err != nil {
			return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidParams, "invalid params", err.Error())
		}
		chainName := normalizeChain(p.Chain)
		if chainName != "tron" {
			return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidParams, "unsupported chain", nil)
		}
		result, err := s.tron.GetTransaction(ctx, p.TxID)
		return respondChain(req.ID, result, err)
	case "sendRawTransaction":
		var p sendParams
		if err := jsonrpc.UnmarshalParams(req.Params, &p); err != nil {
			return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidParams, "invalid params", err.Error())
		}
		chainName := normalizeChain(p.Chain)
		if chainName != "tron" {
			return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidParams, "unsupported chain", nil)
		}
		result, err := s.tron.SendRawTransaction(ctx, p.Tx)
		return respondChain(req.ID, result, err)
	case "tron_getAccountResource":
		var p resourceParams
		if err := jsonrpc.UnmarshalParams(req.Params, &p); err != nil {
			return jsonrpc.ErrorResponse(req.ID, jsonrpc.InvalidParams, "invalid params", err.Error())
		}
		result, err := s.tron.GetAccountResource(ctx, p.Address)
		return respondChain(req.ID, result, err)
	default:
		return jsonrpc.ErrorResponse(req.ID, jsonrpc.MethodNotFound, "method not found", nil)
	}
}

func respondChain[T any](id json.RawMessage, result T, err error) *jsonrpc.Response {
	if err == nil {
		return jsonrpc.ResultResponse(id, result)
	}
	if errors.Is(err, tron.ErrInvalidAddress) || errors.Is(err, tron.ErrInvalidTx) || errors.Is(err, tron.ErrInvalidTxID) {
		return jsonrpc.ErrorResponse(id, jsonrpc.InvalidParams, "invalid params", err.Error())
	}
	return jsonrpc.ErrorResponse(id, jsonrpc.InternalError, "upstream error", err.Error())
}

func normalizeChain(chain string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	if chain == "" {
		return "tron"
	}
	return chain
}

func filterResponses(responses []*jsonrpc.Response) []*jsonrpc.Response {
	filtered := make([]*jsonrpc.Response, 0, len(responses))
	for _, resp := range responses {
		if resp != nil {
			filtered = append(filtered, resp)
		}
	}
	return filtered
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type clientContextKey string

const (
	clientSubjectKey clientContextKey = "client_subject"
	clientSerialKey  clientContextKey = "client_serial"
	clientFPKey      clientContextKey = "client_fingerprint"
)

func withClientIdentity(ctx context.Context, identity ClientIdentity) context.Context {
	ctx = context.WithValue(ctx, clientSubjectKey, identity.Subject)
	ctx = context.WithValue(ctx, clientSerialKey, identity.Serial)
	ctx = context.WithValue(ctx, clientFPKey, identity.Fingerprint)
	return ctx
}

func clientIdentityFromContext(ctx context.Context) (string, string, string) {
	subject, _ := ctx.Value(clientSubjectKey).(string)
	serial, _ := ctx.Value(clientSerialKey).(string)
	fingerprint, _ := ctx.Value(clientFPKey).(string)
	if subject == "" {
		subject = "unknown"
	}
	return subject, serial, fingerprint
}
