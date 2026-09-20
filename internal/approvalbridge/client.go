package approvalbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/itolstov/racg/internal/httpapi"
	"time"
)

type Client struct {
	socketPath string
	http       *http.Client
}

func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		http: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *Client) do(method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "http://approvalbridge"+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		if payload.Error != "" {
			return fmt.Errorf("%s", payload.Error)
		}
		return fmt.Errorf("bridge request failed: %s", resp.Status)
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(output)
}

func (c *Client) Challenge() (string, error) {
	var response struct {
		Challenge string `json:"challenge"`
	}
	if err := c.do(http.MethodGet, "/v1/challenge", nil, &response); err != nil {
		return "", err
	}
	return response.Challenge, nil
}

func (c *Client) Pending() ([]httpapi.PhoneRequest, error) {
	var response struct {
		Requests []httpapi.PhoneRequest `json:"requests"`
	}
	if err := c.do(http.MethodGet, "/v1/pending", nil, &response); err != nil {
		return nil, err
	}
	return response.Requests, nil
}

func (c *Client) Request(requestID string) (httpapi.PhoneRequest, error) {
	var request httpapi.PhoneRequest
	err := c.do(http.MethodGet, "/v1/request?id="+url.QueryEscape(requestID), nil, &request)
	return request, err
}

func (c *Client) Decide(decision PhoneDecision) error {
	return c.do(http.MethodPost, "/v1/decision", decision, nil)
}

func (c *Client) Pair(code, deviceID string, publicKey []byte) error {
	return c.do(http.MethodPost, "/v1/pair", map[string]any{
		"code":       code,
		"device_id":  deviceID,
		"public_key": publicKey,
	}, nil)
}
