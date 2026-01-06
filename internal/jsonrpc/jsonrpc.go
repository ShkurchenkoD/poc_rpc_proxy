package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

var (
	ErrEmptyBatch = errors.New("empty batch")
)

func DecodeRequests(body []byte) ([]Request, bool, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false, ErrEmptyBatch
	}

	if trimmed[0] == '[' {
		var reqs []Request
		if err := json.Unmarshal(trimmed, &reqs); err != nil {
			return nil, false, err
		}
		if len(reqs) == 0 {
			return nil, true, ErrEmptyBatch
		}
		return reqs, true, nil
	}

	var req Request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return nil, false, err
	}

	return []Request{req}, false, nil
}

func IsNotification(req Request) bool {
	if len(req.ID) == 0 {
		return true
	}
	trimmed := bytes.TrimSpace(req.ID)
	return bytes.Equal(trimmed, []byte("null"))
}

func ValidateRequest(req Request) error {
	if req.JSONRPC != "2.0" {
		return fmt.Errorf("jsonrpc must be 2.0")
	}
	if req.Method == "" {
		return fmt.Errorf("method is required")
	}
	if len(req.ID) > 0 {
		var id any
		if err := json.Unmarshal(req.ID, &id); err != nil {
			return fmt.Errorf("id must be string, number, or null")
		}
		switch id.(type) {
		case string, float64, nil:
		default:
			return fmt.Errorf("id must be string, number, or null")
		}
	}
	return nil
}

func ErrorResponse(id json.RawMessage, code int, message string, data any) *Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

func ResultResponse(id json.RawMessage, result any) *Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func UnmarshalParams(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		return fmt.Errorf("params are required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}
