package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
)

const AdminProtocolVersion = 1

const (
	AdminMethodListDevices  = "v1/admin.list-devices"
	AdminMethodRotateDevice = "v1/admin.rotate-device"
	AdminMethodRevokeDevice = "v1/admin.revoke-device"
	AdminMethodListAgents   = "v1/admin.list-agents"
	AdminMethodRotateAgent  = "v1/admin.rotate-agent"
	AdminMethodRevokeAgent  = "v1/admin.revoke-agent"
)

type AdminRequest struct {
	Version int             `json:"version"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type AdminResponse struct {
	Version int             `json:"version"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type AdminCredentialParams struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"public_key,omitempty"`
}

type AdminCredentialsResult struct {
	Credentials []authority.TrustedCredential `json:"credentials"`
}

type AdminResult struct {
	OK bool `json:"ok"`
}

// AdminAuthority is the trusted local registry surface. It contains no
// decision, execution or server-signing methods.
type AdminAuthority interface {
	ListDevicesTrusted(context.Context) ([]authority.TrustedCredential, error)
	RotateDeviceTrusted(context.Context, string, ed25519.PublicKey) error
	RevokeTrusted(context.Context, string) error
	ListAgentsTrusted(context.Context) ([]authority.TrustedCredential, error)
	RotateAgentTrusted(context.Context, string, ed25519.PublicKey) error
	RevokeAgentTrusted(context.Context, string) error
}

// AdminClient talks to the authority's peer-authenticated local admin socket.
// The peer UID/GID is the credential; requests carry no bearer token.
type AdminClient struct {
	mu      sync.Mutex
	conn    io.ReadWriter
	encoder *json.Encoder
	decoder *json.Decoder
	nextID  uint64
}

func NewAdminClient(conn io.ReadWriter) (*AdminClient, error) {
	if conn == nil {
		return nil, errors.New("admin connection required")
	}
	return &AdminClient{
		conn:    conn,
		encoder: json.NewEncoder(conn),
		decoder: json.NewDecoder(conn),
	}, nil
}

func (c *AdminClient) ListDevices(ctx context.Context) ([]authority.TrustedCredential, error) {
	var result AdminCredentialsResult
	return result.Credentials, c.call(ctx, AdminMethodListDevices, nil, &result)
}

func (c *AdminClient) RotateDevice(ctx context.Context, deviceID string, key ed25519.PublicKey) error {
	var result AdminResult
	return c.call(ctx, AdminMethodRotateDevice, AdminCredentialParams{ID: deviceID, PublicKey: append([]byte(nil), key...)}, &result)
}

func (c *AdminClient) RevokeDevice(ctx context.Context, deviceID string) error {
	var result AdminResult
	return c.call(ctx, AdminMethodRevokeDevice, AdminCredentialParams{ID: deviceID}, &result)
}

func (c *AdminClient) ListAgents(ctx context.Context) ([]authority.TrustedCredential, error) {
	var result AdminCredentialsResult
	return result.Credentials, c.call(ctx, AdminMethodListAgents, nil, &result)
}

func (c *AdminClient) RotateAgent(ctx context.Context, clientID string, key ed25519.PublicKey) error {
	var result AdminResult
	return c.call(ctx, AdminMethodRotateAgent, AdminCredentialParams{ID: clientID, PublicKey: append([]byte(nil), key...)}, &result)
}

func (c *AdminClient) RevokeAgent(ctx context.Context, clientID string) error {
	var result AdminResult
	return c.call(ctx, AdminMethodRevokeAgent, AdminCredentialParams{ID: clientID}, &result)
}

func (c *AdminClient) call(ctx context.Context, method string, params, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	request := AdminRequest{Version: AdminProtocolVersion, ID: c.nextID, Method: method}
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encode admin request: %w", err)
		}
		request.Params = encoded
	}
	if err := c.encoder.Encode(request); err != nil {
		return fmt.Errorf("write admin request: %w", err)
	}
	var response AdminResponse
	if err := c.decoder.Decode(&response); err != nil {
		return fmt.Errorf("read admin response: %w", err)
	}
	if response.Version != AdminProtocolVersion || response.ID != request.ID {
		return errors.New("admin response mismatch")
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	if len(response.Result) == 0 {
		return errors.New("admin response missing result")
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		return fmt.Errorf("decode admin result: %w", err)
	}
	return nil
}

func ServeAdminUnix(ctx context.Context, listener *broker.AuthorityUnixListener, admin broker.PeerCredentials, backend AdminAuthority) error {
	return broker.ServeUnix(ctx, listener, admin, func(ctx context.Context, conn io.ReadWriter) error {
		return serveAdmin(ctx, backend, conn)
	})
}

// ConnectAdmin prepares no mutable broker state and opens the peer-verified
// trusted administration client.
func ConnectAdmin(ctx context.Context, config AuthorityConfig) (*AdminClient, func(), error) {
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}
	conn, closeConn, err := broker.DialUnix(ctx, config.AdminSocket, broker.PeerCredentials{
		UID: config.AdminUID,
		GID: config.AdminGID,
	})
	if err != nil {
		return nil, nil, err
	}
	client, err := NewAdminClient(conn)
	if err != nil {
		closeConn()
		return nil, nil, err
	}
	return client, closeConn, nil
}

func serveAdmin(ctx context.Context, backend AdminAuthority, conn io.ReadWriter) error {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var request AdminRequest
		if err := decoder.Decode(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		result, err := handleAdmin(ctx, backend, request)
		response := AdminResponse{Version: AdminProtocolVersion, ID: request.ID}
		if err != nil {
			response.Error = err.Error()
		} else {
			encoded, encodeErr := json.Marshal(result)
			if encodeErr != nil {
				response.Error = "encode admin result"
			} else {
				response.Result = encoded
			}
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
}

func handleAdmin(ctx context.Context, backend AdminAuthority, request AdminRequest) (any, error) {
	if request.Version != AdminProtocolVersion {
		return nil, errors.New("unsupported admin protocol version")
	}
	switch request.Method {
	case AdminMethodListDevices:
		credentials, err := backend.ListDevicesTrusted(ctx)
		return AdminCredentialsResult{Credentials: credentials}, err
	case AdminMethodListAgents:
		credentials, err := backend.ListAgentsTrusted(ctx)
		return AdminCredentialsResult{Credentials: credentials}, err
	}
	var params AdminCredentialParams
	if len(request.Params) == 0 || json.Unmarshal(request.Params, &params) != nil || params.ID == "" {
		return nil, errors.New("invalid admin credential request")
	}
	switch request.Method {
	case AdminMethodRotateDevice:
		return AdminResult{OK: true}, backend.RotateDeviceTrusted(ctx, params.ID, ed25519.PublicKey(params.PublicKey))
	case AdminMethodRevokeDevice:
		return AdminResult{OK: true}, backend.RevokeTrusted(ctx, params.ID)
	case AdminMethodRotateAgent:
		return AdminResult{OK: true}, backend.RotateAgentTrusted(ctx, params.ID, ed25519.PublicKey(params.PublicKey))
	case AdminMethodRevokeAgent:
		return AdminResult{OK: true}, backend.RevokeAgentTrusted(ctx, params.ID)
	default:
		return nil, errors.New("unknown admin method")
	}
}
