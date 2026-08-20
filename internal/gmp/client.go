package gmp

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var ErrNotFound = errors.New("gmp: resource not found")

type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type Client struct {
	socketPath string
	username   string
	password   string
	timeout    time.Duration
	dial       DialFunc
}

type ProtocolError struct {
	Command    string
	Status     string
	StatusText string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("gmp: %s failed with status %s: %s", e.Command, e.Status, e.StatusText)
}

func New(socketPath, username, password string, timeout time.Duration) *Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &Client{
		socketPath: socketPath,
		username:   username,
		password:   password,
		timeout:    timeout,
		dial:       dialer.DialContext,
	}
}

func NewWithDialer(username, password string, timeout time.Duration, dial DialFunc) *Client {
	return &Client{
		username: username,
		password: password,
		timeout:  timeout,
		dial:     dial,
	}
}

func (c *Client) call(ctx context.Context, request, response any) error {
	connection, err := c.dial(ctx, "unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("gmp: connecting to unix socket: %w", err)
	}
	defer connection.Close()

	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("gmp: setting connection deadline: %w", err)
	}

	encoder := xml.NewEncoder(connection)
	decoder := xml.NewDecoder(io.LimitReader(connection, 32<<20))
	authRequest := authenticateRequest{
		Credentials: credentials{
			Username: c.username,
			Password: c.password,
		},
	}
	var authResponse responseStatus
	if err := exchange(encoder, decoder, authRequest, &authResponse); err != nil {
		return fmt.Errorf("gmp: authenticating: %w", err)
	}
	if err := checkStatus("authenticate", authResponse); err != nil {
		return err
	}
	if err := exchange(encoder, decoder, request, response); err != nil {
		return fmt.Errorf("gmp: exchanging command: %w", err)
	}
	return nil
}

func exchange(encoder *xml.Encoder, decoder *xml.Decoder, request, response any) error {
	if err := encoder.Encode(request); err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}
	if err := encoder.Flush(); err != nil {
		return fmt.Errorf("flushing request: %w", err)
	}
	if err := decoder.Decode(response); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func checkStatus(command string, status responseStatus) error {
	if strings.HasPrefix(status.Status, "2") {
		return nil
	}
	return &ProtocolError{
		Command:    command,
		Status:     status.Status,
		StatusText: status.StatusText,
	}
}

type responseStatus struct {
	Status     string `xml:"status,attr"`
	StatusText string `xml:"status_text,attr"`
}

type createResponse struct {
	responseStatus
	ID string `xml:"id,attr"`
}

type authenticateRequest struct {
	XMLName     xml.Name    `xml:"authenticate"`
	Credentials credentials `xml:"credentials"`
}

type credentials struct {
	Username string `xml:"username"`
	Password string `xml:"password"`
}
