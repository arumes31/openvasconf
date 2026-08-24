package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

type Manager interface {
	Status(ctx context.Context) (Status, error)
	Configure(ctx context.Context, policy Policy) error
	Trigger(ctx context.Context, kind Kind, request TriggerRequest) (Operation, error)
	Acknowledge(ctx context.Context) error
}

type Client struct {
	httpClient *http.Client
}

func NewClient(socketPath string, timeout time.Duration) *Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
		MaxIdleConns:       2,
		IdleConnTimeout:    30 * time.Second,
	}
	return &Client{httpClient: &http.Client{Transport: transport, Timeout: timeout}}
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	var result Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &result); err != nil {
		return Status{}, err
	}
	return result, nil
}

func (c *Client) Configure(ctx context.Context, policy Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, "/v1/policy", policy, nil)
}

func (c *Client) Trigger(
	ctx context.Context,
	kind Kind,
	request TriggerRequest,
) (Operation, error) {
	var result Operation
	path := ""
	switch kind {
	case KindCheck:
		path = "/v1/operations/check"
	case KindFeed:
		path = "/v1/operations/feed"
	case KindStack:
		path = "/v1/operations/stack"
	default:
		return Operation{}, fmt.Errorf("updater: unsupported operation kind %q", kind)
	}
	if err := c.do(ctx, http.MethodPost, path, request, &result); err != nil {
		return Operation{}, err
	}
	return result, nil
}

func (c *Client) Acknowledge(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/acknowledge", struct{}{}, nil)
}

func (c *Client) do(
	ctx context.Context,
	method, path string,
	input, output any,
) (returnErr error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encoding updater request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://updater"+path, body)
	if err != nil {
		return fmt.Errorf("creating updater request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("closing updater response: %w", err))
		}
	}()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("reading updater response: %w", err)
	}
	if len(contents) > maxResponseBytes {
		return errors.New("updater: response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure ErrorResponse
		_ = json.Unmarshal(contents, &failure)
		message := strings.TrimSpace(failure.Error)
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		switch response.StatusCode {
		case http.StatusConflict:
			return fmt.Errorf("%w: %s", ErrBusy, message)
		case http.StatusLocked:
			return fmt.Errorf("%w: %s", ErrPaused, message)
		default:
			return fmt.Errorf("updater request failed: %s", message)
		}
	}
	if output == nil || len(contents) == 0 {
		return nil
	}
	if err := json.Unmarshal(contents, output); err != nil {
		return fmt.Errorf("decoding updater response: %w", err)
	}
	return nil
}
