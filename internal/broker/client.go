package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/itolstov/racg/internal/approval"
)

// AuthorityClient is the broker-side connection to the narrow authority
// protocol. It holds no authority signing key and cannot execute operations.
// Calls are serialized so one local connection needs no framing state machine.
type AuthorityClient struct {
	mu      sync.Mutex
	conn    io.ReadWriter
	encoder *json.Encoder
	decoder *json.Decoder
	nextID  uint64
}

func NewAuthorityClient(conn io.ReadWriter) (*AuthorityClient, error) {
	if conn == nil {
		return nil, errors.New("authority connection required")
	}
	return &AuthorityClient{
		conn:    conn,
		encoder: json.NewEncoder(conn),
		decoder: json.NewDecoder(conn),
	}, nil
}

func (c *AuthorityClient) SubmitAgent(ctx context.Context, signed approval.SignedSubmission) (approval.SignedRequest, error) {
	var result approval.SignedRequest
	return result, c.call(ctx, MethodSubmitAgent, signed, &result)
}

func (c *AuthorityClient) LookupSubmission(ctx context.Context, signed approval.SignedLookup) (approval.SignedLookupResult, error) {
	var result approval.SignedLookupResult
	return result, c.call(ctx, MethodLookupSubmission, signed, &result)
}

func (c *AuthorityClient) StageUpload(ctx context.Context, submission UploadSubmission) (approval.StagedUpload, error) {
	var result approval.StagedUpload
	return result, c.call(ctx, MethodStageUpload, submission, &result)
}

func (c *AuthorityClient) SubmitDecision(ctx context.Context, submission DecisionSubmission) (approval.SignedDecisionReceipt, error) {
	var result approval.SignedDecisionReceipt
	return result, c.call(ctx, MethodSubmitDecision, submission, &result)
}

func (c *AuthorityClient) LookupDecision(ctx context.Context, signed approval.SignedDecisionLookup) (approval.SignedDecisionLookupResult, error) {
	var result approval.SignedDecisionLookupResult
	return result, c.call(ctx, MethodLookupDecision, signed, &result)
}

func (c *AuthorityClient) call(ctx context.Context, method string, params, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	request := Request{Version: ProtocolVersion, ID: c.nextID, Method: method}
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encode authority request: %w", err)
		}
		request.Params = encoded
	}
	if err := c.encoder.Encode(request); err != nil {
		return fmt.Errorf("write authority request: %w", err)
	}
	var response Response
	if err := c.decoder.Decode(&response); err != nil {
		return fmt.Errorf("read authority response: %w", err)
	}
	if response.Version != ProtocolVersion {
		return errors.New("unsupported authority response version")
	}
	if response.ID != request.ID {
		return errors.New("authority response mismatch")
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	if len(response.Result) == 0 {
		return errors.New("authority response missing result")
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		return fmt.Errorf("decode authority result: %w", err)
	}
	return nil
}
